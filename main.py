import socket
import struct


class custom_packet:
    def __init__(self, flag, number_of_fragments=None, fragment_order=None, crc=None,
                 data=None, filename=None):
        self.flag = flag
        self.number_of_fragments = number_of_fragments
        self.fragment_order = fragment_order
        self.crc = crc
        self.data = data
        self.filename = filename

    def __bytes__(self):
        flag_bytes = struct.pack('!B', self.flag)
        number_of_fragments_bytes = struct.pack('!BBB', (self.number_of_fragments >> 16) & 0xFF, (self.number_of_fragments >> 8) & 0xFF, self.number_of_fragments & 0xFF) if self.number_of_fragments is not None else b''
        fragment_order_bytes = struct.pack('!BBB', (self.fragment_order >> 16) & 0xFF, (self.fragment_order >> 8) & 0xFF, self.fragment_order & 0xFF) if self.fragment_order is not None else b''
        crc_bytes = struct.pack('!I', self.crc) if self.crc is not None else b''
        filename_bytes = self.filename.encode('utf-8') if self.filename is not None else b''
        data_bytes = self.data if self.data is not None else b''

        return flag_bytes + number_of_fragments_bytes + fragment_order_bytes + crc_bytes + filename_bytes + data_bytes


def server():
    port = input("Zadajte port:")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(60)
    try:
        server_socket.bind(("", int(port)))
        received_info, address = server_socket.recvfrom(1500)
        first_init_packet = custom_packet(flag=1)
        server_socket.sendto(bytes(first_init_packet), address)
        print("Počiatočné spojenie nadviazané, môže začať komunikácia.")
        server_after_init(server_socket)

    except server_socket.timeout:
        print("Klient neinicializoval spojenie, uzatvaram.")
        server_socket.close()
        return

def server_after_init(server_socket):
    while True:
        try:
            server_socket.settimeout(60)
            while True:
                received_info, address = server_socket.recvfrom(1500)
                flag = custom_packet(
                    *struct.unpack('!B', received_info[:1]))

                if flag == 2:
                    print("keepalive on")
                    keepalive_packet = custom_packet(flag=2)
                    server_socket.sendto(bytes(keepalive_packet), address)

                elif flag == 3 or flag == 4:
                    """
                    number_of_fragments = received_packet.number_of_fragments
                    file_name = received_packet.filename.decode('utf-8')
                    print("Received data packet:")
                    print(f"Flag: {flag}")
                    print(f"Number of Fragments: {number_of_fragments}")
                    print(f"Filename: {file_name}")
                    data_process_server(server_socket, flag, number_of_fragments, file_name)
                    """

        except socket.timeout:
            print("kocniem")
            return

def data_process_server(server_socket, flag, number_of_fragments, file_name):
    return


def client():
    port = input("Zadajte port:")
    ip = input("Zadajte IP adresu:")
    return

def test():
    test_packet = custom_packet(flag=3, number_of_fragments=5)

    # Call the __bytes__ method to get the byte representation
    packet_bytes = bytes(test_packet)
    packet_bytes = packet_bytes[:1] + b'\x00' + packet_bytes[1:]

    # Display the byte representation
    print("Byte representation:", packet_bytes)

    # Unpack the bytes dynamically
    fields = ['B', 'I']  # Assuming 'B' for flag, 'BBB' for number_of_fragments

    # Unpack the fixed-length fields
    offset = 0
    parsed_values = []

    for field_format in fields:
        field_size = struct.calcsize(field_format)
        field_value = struct.unpack('!' + field_format, packet_bytes[offset:offset + field_size])[0]
        parsed_values.append(field_value)
        offset += field_size

    print("Parsed values:")
    print(f"Flag: {parsed_values[0]}")
    print(f"Number of Fragments: {parsed_values[1]}")


if __name__ == "__main__":
    print("menu:")
    user_input = input("Zadaj server(klient")
    if user_input == "server":
        server()
    elif user_input == "klient":
        client()
    elif user_input == "test":
        test()