use image::DynamicImage;
use std::io::Read;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "join-qr" => {
            if args.len() != 4 {
                eprintln!("Usage: cargo xtask join-qr <input.tar> <output.png>");
                std::process::exit(1);
            }
            gen_combined_qr(&args[2], &args[3])?;
        }
        "mix-tar" => {
            if args.len() != 4 {
                eprintln!("Usage: cargo xtask mix-tar <input.tar> <output.tar>");
                std::process::exit(1);
            }
            gen_mixed_tar(&args[2], &args[3])?;
        }
        "missing-fragment" => {
            if args.len() != 5 {
                eprintln!("Usage: cargo xtask missing-fragment <input.tar> <output.tar> <index>");
                std::process::exit(1);
            }
            let index: usize = args[4].parse()?;
            gen_missing_fragment(&args[2], &args[3], index)?;
        }
        "blank-image" => {
            if args.len() != 3 {
                eprintln!("Usage: cargo xtask blank-image <output.png>");
                std::process::exit(1);
            }
            gen_blank_image(&args[2])?;
        }
        "unpack-tar" => {
            if args.len() != 4 {
                eprintln!("Usage: cargo xtask unpack-tar <input.tar> <output-dir>");
                std::process::exit(1);
            }
            cmd_unpack_tar(&args[2], &args[3])?;
        }
        "png-to-jpeg" => {
            if args.len() != 4 {
                eprintln!("Usage: cargo xtask png-to-jpeg <input.png> <output.jpg>");
                std::process::exit(1);
            }
            cmd_png_to_jpeg(&args[2], &args[3])?;
        }
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    }
    Ok(())
}

fn print_usage() {
    eprintln!("Usage: cargo xtask <command> [args...]");
    eprintln!("Commands:");
    eprintln!(
        "  join-qr <input.tar> <output.png>                   — combine QR images from TAR into a single PNG grid"
    );
    eprintln!(
        "  mix-tar <input.tar> <output.tar>                   — repack TAR with alternating PNG/JPEG images"
    );
    eprintln!(
        "  missing-fragment <input.tar> <output.tar> <index>  — remove fragment at index (1-based)"
    );
    eprintln!(
        "  blank-image <output.png>                           — generate a blank white image"
    );
    eprintln!(
        "  unpack-tar <input.tar> <output-dir>                — unpack images from TAR into a directory"
    );
    eprintln!("  png-to-jpeg <input.png> <output.jpg>               — convert PNG image to JPEG");
}

fn unpack_tar_bytes(tar_path: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let tar_data = std::fs::read(tar_path)?;
    let mut archive = tar::Archive::new(tar_data.as_slice());
    let mut entries = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        entries.push(data);
    }
    Ok(entries)
}

fn unpack_tar_images(tar_path: &str) -> anyhow::Result<Vec<DynamicImage>> {
    unpack_tar_bytes(tar_path)?
        .into_iter()
        .map(|data| image::load_from_memory(&data).map_err(anyhow::Error::from))
        .collect()
}

fn png_to_jpeg(image: &DynamicImage) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::new();
    image.write_to(
        &mut std::io::Cursor::new(&mut data),
        image::ImageFormat::Jpeg,
    )?;
    Ok(data)
}

fn cmd_unpack_tar(tar_path: &str, output_dir: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(output_dir)?;
    let images = unpack_tar_images(tar_path)?;
    for (i, image) in images.iter().enumerate() {
        let path = format!("{}/{:05}.png", output_dir, i + 1);
        image.save(&path)?;
    }
    println!("Unpacked {} images to {output_dir}", images.len());
    Ok(())
}

fn cmd_png_to_jpeg(input: &str, output: &str) -> anyhow::Result<()> {
    let image = image::open(input)?;
    let data = png_to_jpeg(&image)?;
    std::fs::write(output, &data)?;
    println!("Converted {input} to {output}");
    Ok(())
}

fn gen_combined_qr(tar_path: &str, png_path: &str) -> anyhow::Result<()> {
    use image::RgbaImage;
    let images = unpack_tar_images(tar_path)?;
    let cols = 2u32;
    let rows = (images.len() as u32).div_ceil(cols);
    let cell_width = images.iter().map(|img| img.width()).max().unwrap_or(0);
    let cell_height = images.iter().map(|img| img.height()).max().unwrap_or(0);
    let total_width = cell_width * cols;
    let total_height = cell_height * rows;
    let mut combined =
        RgbaImage::from_pixel(total_width, total_height, image::Rgba([255, 255, 255, 255]));
    for (i, img) in images.iter().enumerate() {
        let col = (i as u32) % cols;
        let row = (i as u32) / cols;
        let x = col * cell_width;
        let y = row * cell_height;
        image::imageops::overlay(&mut combined, &img.to_rgba8(), x.into(), y.into());
    }
    DynamicImage::ImageRgba8(combined).save(png_path)?;
    println!(
        "Generated {png_path} ({total_width}x{total_height}, {cols}x{rows} grid, {} images)",
        images.len()
    );
    Ok(())
}

fn tar_append(archive: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) -> anyhow::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, name, data)?;
    Ok(())
}

fn gen_mixed_tar(input: &str, output: &str) -> anyhow::Result<()> {
    let entries = unpack_tar_bytes(input)?;
    let mut archive = tar::Builder::new(Vec::new());
    for (i, png_data) in entries.iter().enumerate() {
        let (ext, data) = if i % 2 == 0 {
            ("png", png_data.clone())
        } else {
            let img = image::load_from_memory(png_data)?;
            ("jpg", png_to_jpeg(&img)?)
        };
        let name = format!("{:05}.{ext}", i + 1);
        tar_append(&mut archive, &name, &data)?;
    }
    archive.finish()?;
    let tar_data = archive.into_inner()?;
    std::fs::write(output, &tar_data)?;
    println!(
        "Generated {output} ({} images, mixed PNG/JPEG)",
        entries.len()
    );
    Ok(())
}

fn gen_missing_fragment(input: &str, output: &str, skip_index: usize) -> anyhow::Result<()> {
    let entries = unpack_tar_bytes(input)?;
    let mut archive = tar::Builder::new(Vec::new());
    for (pos, data) in entries
        .iter()
        .enumerate()
        .filter(|(i, _)| i + 1 != skip_index)
        .map(|(_, data)| data)
        .enumerate()
    {
        let name = format!("{:05}.png", pos + 1);
        tar_append(&mut archive, &name, data)?;
    }
    archive.finish()?;
    let tar_data = archive.into_inner()?;
    std::fs::write(output, &tar_data)?;
    println!(
        "Generated {output} ({} entries, skipped index {skip_index})",
        entries.len() - 1
    );
    Ok(())
}

fn gen_blank_image(output: &str) -> anyhow::Result<()> {
    let img = image::GrayImage::from_pixel(100, 100, image::Luma([255u8]));
    DynamicImage::ImageLuma8(img).save(output)?;
    println!("Generated {output} (100x100 blank white)");
    Ok(())
}
