use std::{thread::sleep, time::Duration};

use crate::{
    common::Serializable,
    cpf::{
        CommonPacketHeader, CommonPacketList, ConnectedAddressItem, ConnectedDataItem,
        NullAddressItem, UnconnectedDataItem,
    },
    encapsulation::{
        EtherNetIPHeader, RegisterSession, SendRRData, SendUnitData, UnregisterSession, NOP,
    },
    udp::UdpENIPClient,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use cip::{
    cip::{CipClass, Client, DataResult, EPath, LogicalSegment, LogicalType, MessageRouterRequest},
    objects::connection_manager::ForwardOpenRequest,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, Interest},
    net::TcpStream,
};

pub struct TcpEnipClient {
    pub session_handle: u32,
    connection_id: u32,
    tcp: TcpStream,
}

pub enum EnipClient {
    Udp(UdpENIPClient),
    Tcp(TcpEnipClient),
}

impl TcpEnipClient {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            session_handle: 0,
            tcp: stream,
            connection_id: 0,
        }
    }

    pub async fn send_packet(&mut self, packet: Vec<u8>) {
        println!("send packet: {:?} length: {}", packet, packet.len());
        let ready = self.tcp.ready(Interest::WRITABLE).await.unwrap();
        if ready.is_writable() {
            match &self.tcp.write_all(&packet).await {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    //x.push(work_item).await;
                }
            }
        }
    }

    async fn read_packet(&mut self) -> Vec<u8> {
        let _ready = self.tcp.readable().await.unwrap();

        let mut data: Vec<u8> = alloc::vec![0; 65535];
        match self.tcp.read(&mut data).await {
            Ok(n) => {
                if n >= 24 {
                    let mut local = alloc::vec![0; n];
                    for i in 0..n {
                        local[i] = data[i]
                    }
                    println!("read_packet: {:?}", local);
                    return local;
                }

                return alloc::vec![];
            }
            Err(e) => {
                return alloc::vec![];
            }
        }
    }
}

#[async_trait]
impl Client for TcpEnipClient {
    async fn begin_session(&mut self) {
        let header = RegisterSession {
            header: EtherNetIPHeader {
                command: 0x0065,
                length: 4,
                session_handle: 0,
                status: 0,
                sender_context: 0x5f7079636f6d6d5f,
                options: 0,
            },
            version: 1,
            options: 0,
        };
        let tx_buf = header.serialize();
        println!("begin session send: {:?}", tx_buf);
        let _ = self.send_packet(tx_buf).await;

        let buf = self.read_packet().await;
        println!("begin session receive: {:?}", buf);
        let reply = RegisterSession::deserialize(&buf).unwrap();
        println!(
            "begin session reply: {:?} RegisterSession not used",
            reply.0.to_vec(),
        );

        self.session_handle = reply.1.header.session_handle;
    }

    async fn close_session(&mut self) {
        let unreg = UnregisterSession {
            command: 0x0066,
            length: 0,
            session_handle: self.session_handle,
            status: 0,
            sender_context: 0x5f7079636f6d6d5f,
            options: 0,
        };
        let _ = self.send_packet(unreg.serialize());
        let _ = self.tcp.shutdown().await;
    }

    async fn send_unconnected(&mut self, packet: Vec<u8>) {
        let header = EtherNetIPHeader {
            command: 0x6F,
            session_handle: self.session_handle,
            length: (packet.len() as u16 + 16),
            status: 0,
            sender_context: 0x5f7079636f6d6d5f,
            options: 0,
        };
        let mut list: CommonPacketList = CommonPacketList::new();
        list.null_address_item.push(NullAddressItem {
            type_id: 0,
            length: 0,
        });
        list.unconnected_data_item.push(UnconnectedDataItem {
            header: CommonPacketHeader {
                type_id: 0xb2,
                length: packet.len() as u16,
            },
            data: packet,
        });
        let packet = SendRRData {
            header: header,
            interface_handle: 0,
            timeout: 100,
            items: list,
        };
        self.send_packet(packet.serialize()).await;
    }

    async fn send_connected(&mut self, packet: Vec<u8>) {
        let header = EtherNetIPHeader {
            command: 0x70,
            session_handle: self.session_handle,
            length: (packet.len() as u16 + 16 + 4),
            status: 0,
            sender_context: 0x5f7079636f6d6d5f,
            options: 0,
        };
        let mut list: CommonPacketList = CommonPacketList::new();
        list.connected_addr_item.push(ConnectedAddressItem {
            header: CommonPacketHeader {
                type_id: 0xA1,
                length: 4,
            },
            addr: self.connection_id,
        });
        list.connected_data_item.push(ConnectedDataItem {
            header: CommonPacketHeader {
                type_id: 0xB1,
                length: packet.len() as u16,
            },
            data: packet,
        });
        let packet = SendUnitData {
            header: header,
            interface_handle: 0,
            timeout: 100,
            items: list,
        };
        self.send_packet(packet.serialize()).await;
    }

    async fn send_nop(&mut self) {
        let header = EtherNetIPHeader {
            command: 0x00,
            session_handle: self.connection_id,
            length: 0,
            status: 0,
            sender_context: 0,
            options: 0,
        };
        let packet = NOP {
            header: header,
            data: Vec::new(),
        };
        self.send_packet(packet.serialize()).await;
    }

    async fn read_data(&mut self) -> DataResult {
        let result = self.read_packet().await;
        let enip: (&[u8], EtherNetIPHeader) = EtherNetIPHeader::deserialize(&result).unwrap();
        let mut data = Vec::new();

        if enip.1.command == 0x006F {
            let rrdata = SendRRData::deserialize(&result).unwrap();

            for item in rrdata.1.items.unconnected_data_item {
                data.extend_from_slice(&item.data);
            }
        }

        return DataResult {
            status: enip.1.status,
            data: result, // return all the received data so I deserialize it again
        };
    }

    async fn forward_open(&mut self) {
        let mut epath = EPath::new();
        let connection_manager_class = LogicalSegment::init(
            LogicalType::ClassId as u8,
            CipClass::ConnectionManager as u32,
        );
        let connection_manager_instance = LogicalSegment::init(LogicalType::InstanceId as u8, 0x1);
        epath.attributes.push(Box::new(connection_manager_class));
        epath.attributes.push(Box::new(connection_manager_instance));

        let mut forward_open_epath = EPath::new();
        forward_open_epath
            .attributes
            .push(Box::new(LogicalSegment::init(
                LogicalType::ClassId as u8,
                CipClass::MessageRouter as u32,
            )));
        forward_open_epath
            .attributes
            .push(Box::new(LogicalSegment::init(
                LogicalType::InstanceId as u8,
                0x01,
            )));

        // Initial network parameters based on CIP Vol 1, 3-5.5.1.1
        let init_net_params: u16 = 0b_0100_0010_0000_0000; // Equivalent to 0x4200
        let connection_size: u32 = 4000;
        let net_params =
            ((connection_size as u32 & 0xFFFF) | ((init_net_params as u32) << 16)) as u32;
        println!("net params: {:x}", net_params);
        let request = MessageRouterRequest {
            service: 0x5B,
            epath,
            data: cip::common::Serializable::serialize(&ForwardOpenRequest {
                priority: 0x0A,
                timeout_ticks: 0x05,
                ot_network_connection_id: 0x00000000, // client side (labitude)
                to_network_connection_id: 0x71190427, // server side (pump)
                connection_serial_number: 0x0427,     // It should be unique for each connection
                original_vendor_id: 0x1009,           // Vendor ID of the client? Labitude
                original_serial_number: 241216,       // PLC serial number
                connection_timeout_multiplier: 0x07,
                ot_rpi: 0x00204001, // timeout in micro-seconds
                ot_network_parameters: net_params,
                to_rpi: 0x00204001, //timeout in micro-seconds
                to_network_parameters: net_params,
                transport_class: 0xA3,
                connection_path: forward_open_epath,
            }),
        };

        let data_frame = cip::common::Serializable::serialize(&request);
        println!("data frame to send: {:x?}", data_frame);
        self.send_unconnected(data_frame).await;
        println!("forward open sent");

        println!("reading data after forward open ...");
        let data_result = self.read_data().await;
        let (data, enip_header) = EtherNetIPHeader::deserialize(&data_result.data).unwrap();

        if enip_header.command != 0x006f {
            panic!(
                "wrong command! 0x006F expected. {} found",
                enip_header.command
            );
        }

        // self.session_handle = enip_header.session_handle;
        self.connection_id = 0x00000000; //11
    }
}
