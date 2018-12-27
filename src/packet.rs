// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use num_traits::{FromPrimitive, ToPrimitive};

static FRAME_INIT: u8 = 0x80;

#[repr(u8)]
#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum CtapCommand {
    Invalid = 0x00,
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3b,
    Error = 0x3f,
}

impl CtapCommand {
    pub fn to_wire_format(&self) -> u8 {
        match self.to_u8() {
            Some(x) => x,
            None => 0x00,
        }
    }
}

#[repr(u8)]
#[derive(FromPrimitive, Fail, Debug)]
pub enum CtapError {
    #[fail(display = "The command in the request is invalid")]
    InvalidCmd = 0x01,
    #[fail(display = "The parameter(s) in the request is invalid")]
    InvalidPar = 0x02,
    #[fail(display = "The length field (BCNT) is invalid for the request ")]
    InvalidLen = 0x03,
    #[fail(display = "The sequence does not match expected value ")]
    InvalidSeq = 0x04,
    #[fail(display = "The message has timed out ")]
    MsgTimeout = 0x05,
    #[fail(display = "The device is busy for the requesting channel ")]
    ChannelBusy = 0x06,
    #[fail(display = "Command requires channel lock ")]
    LockRequired = 0x0A,
    #[fail(display = "Reserved error")]
    NA = 0x0B,
    #[fail(display = "Unspecified error")]
    Other = 0x7F,
}

pub trait Packet {
    fn from_wire_format(data: &[u8]) -> Self;

    fn to_wire_format(&self) -> &[u8];
}

pub struct InitPacket(pub [u8; 65]);

impl InitPacket {
    pub fn new(cid: &[u8], cmd: &CtapCommand, size: u16, payload: &[u8]) -> InitPacket {
        let mut packet = InitPacket([0; 65]);
        packet.0[1..5].copy_from_slice(cid);
        packet.0[5] = FRAME_INIT | cmd.to_wire_format();
        packet.0[6] = ((size >> 8) & 0xff) as u8;
        packet.0[7] = (size & 0xff) as u8;
        packet.0[8..(payload.len() + 8)].copy_from_slice(payload);
        packet
    }

    pub fn cid(&self) -> &[u8] {
        &self.0[1..5]
    }

    pub fn cmd(&self) -> CtapCommand {
        match CtapCommand::from_u8(self.0[5] ^ FRAME_INIT) {
            Some(cmd) => cmd,
            None => CtapCommand::Invalid,
        }
    }

    pub fn size(&self) -> u16 {
        ((u16::from(self.0[6])) << 8) | u16::from(self.0[7])
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[8..65]
    }
}

impl Packet for InitPacket {
    fn from_wire_format(data: &[u8]) -> InitPacket {
        let mut packet = InitPacket([0; 65]);
        packet.0[1..65].copy_from_slice(data);
        packet
    }

    fn to_wire_format(&self) -> &[u8] {
        &self.0
    }
}

pub struct ContPacket(pub [u8; 65]);

impl ContPacket {
    pub fn new(cid: &[u8], seq: u8, payload: &[u8]) -> ContPacket {
        let mut packet = ContPacket([0; 65]);
        packet.0[1..5].copy_from_slice(cid);
        packet.0[5] = seq;
        packet.0[6..(payload.len() + 6)].copy_from_slice(payload);
        packet
    }

    pub fn cid(&self) -> &[u8] {
        &self.0[1..5]
    }

    pub fn seq(&self) -> u8 {
        self.0[5]
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[6..65]
    }
}

impl Packet for ContPacket {
    fn from_wire_format(data: &[u8]) -> ContPacket {
        let mut packet = ContPacket([0; 65]);
        packet.0[1..65].copy_from_slice(data);
        packet
    }

    fn to_wire_format(&self) -> &[u8] {
        &self.0
    }
}
