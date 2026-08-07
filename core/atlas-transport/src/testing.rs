//! Двусторонняя труба для проверок.
//!
//! Нужна и транспорту WebSocket, и сквозному каналу: обе стороны
//! настоящие, соединение настоящее, сети нет. Проверка на подставном
//! объекте, повторяющем ожидания автора, доказывала бы только сами
//! ожидания.

#![cfg(test)]
#![allow(clippy::indexing_slicing)]

use std::io::{self, Read, Write};
use std::sync::mpsc::{channel, Receiver, Sender};

/// Двусторонняя труба: то, что записано с одной стороны, читается с
/// другой. Нужна, чтобы гонять настоящее соединение без сети.
#[derive(Debug)]
pub(crate) struct Pipe {
    outgoing: Sender<Vec<u8>>,
    incoming: Receiver<Vec<u8>>,
    buffered: Vec<u8>,
    taken: usize,
}

impl Pipe {
    pub(crate) fn duplex() -> (Self, Self) {
        let (left_tx, left_rx) = channel();
        let (right_tx, right_rx) = channel();
        (
            Self {
                outgoing: left_tx,
                incoming: right_rx,
                buffered: Vec::new(),
                taken: 0,
            },
            Self {
                outgoing: right_tx,
                incoming: left_rx,
                buffered: Vec::new(),
                taken: 0,
            },
        )
    }
}

impl Read for Pipe {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.taken == self.buffered.len() {
            match self.incoming.recv() {
                Ok(next) => {
                    self.buffered = next;
                    self.taken = 0;
                }
                // Другая сторона отпущена — это конец потока.
                Err(_) => return Ok(0),
            }
        }
        let take = (self.buffered.len() - self.taken).min(out.len());
        out[..take].copy_from_slice(&self.buffered[self.taken..self.taken + take]);
        self.taken += take;
        Ok(take)
    }
}

impl Write for Pipe {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.outgoing
            .send(data.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "труба закрыта"))?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Пара соединённых концов.
pub(crate) fn duplex() -> (Pipe, Pipe) {
    Pipe::duplex()
}
