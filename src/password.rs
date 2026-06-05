use bstr::{ByteSlice, ByteVec};
use crossterm::cursor::MoveToColumn;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, read};
use crossterm::execute;
use crossterm::terminal::{self};
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn read_password(password_file: Option<PathBuf>) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    if let Some(file_path) = password_file {
        read_password_from_file(&file_path)
    } else {
        read_password_from_tty()
    }
}

fn read_password_from_file(path_buf: &PathBuf) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    let mut password_file = std::fs::File::open(path_buf)?;
    let mut password = Zeroizing::new(Vec::new());
    password_file.read_to_end(&mut password)?;

    Ok(password)
}

fn clear_output(tty: &mut impl Write) -> Result<(), std::io::Error> {
    execute!(
        tty,
        MoveToColumn(0),
        terminal::Clear(terminal::ClearType::CurrentLine)
    )?;
    tty.flush()?;
    Ok(())
}

fn render_password_input(tty: &mut impl Write, len: usize) -> Result<(), std::io::Error> {
    clear_output(tty)?;
    write!(tty, "Enter password: {}", "*".repeat(len))?;
    tty.flush()?;
    Ok(())
}

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

#[cfg(unix)]
fn open_tty() -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new().write(true).open("/dev/tty")
}

#[cfg(windows)]
fn open_tty() -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new().write(true).open("CONOUT$")
}

fn read_password_from_tty() -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    let mut tty = open_tty()?;
    let mut password = Zeroizing::new(Vec::new());
    let mut char_buf = [0u8; 4];
    terminal::enable_raw_mode()?;
    let _guard = RawModeGuard;
    loop {
        render_password_input(&mut tty, password.chars().count())?;
        if let Event::Key(KeyEvent {
            code,
            kind: KeyEventKind::Press,
            ..
        }) = read()?
        {
            match code {
                KeyCode::Enter => break,
                KeyCode::Char(char) => {
                    password.extend_from_slice(char.encode_utf8(&mut char_buf).as_bytes());
                }
                KeyCode::Backspace => {
                    password.pop_char();
                }
                KeyCode::Esc => {
                    clear_output(&mut tty)?;
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    }
    clear_output(&mut tty)?;
    Ok(password)
}
