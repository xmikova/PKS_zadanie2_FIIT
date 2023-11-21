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

def parse_packet(flag, received_info): #TODO
    # Tu pridat if pre kazdy mozny packet ako sa ma rozparsovat

    if flag == 3: #textova sprava
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]

        # Unpack the bytes dynamically
        fields = ['B', 'I']  # Assuming 'B' for flag, 'BBB' for number_of_fragments
        parsed_values = unpack_bytes(fields, packet_bytes)

        flag = parsed_values[0]
        number_of_fragments = parsed_values[1]

        return flag, number_of_fragments

    elif flag == 4: #subor
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]
        bytes_length = len(packet_bytes)
        filename_length = bytes_length - 5

        filename_field = str(filename_length) + "s"

        # Unpack the bytes dynamically
        fields = ['B', 'I', filename_field]  # Assuming 'B' for flag, 'BBB' for number_of_fragments
        parsed_values = unpack_bytes(fields,packet_bytes)

        flag = parsed_values[0]
        number_of_fragments = parsed_values[1]
        filename = parsed_values[2].decode('utf-8')

        return flag, number_of_fragments, filename

    return


def unpack_bytes(fields, packet_bytes):
    offset = 0
    parsed_values = []

    for field_format in fields:
        field_size = struct.calcsize(field_format)
        field_value = struct.unpack('!' + field_format, packet_bytes[offset:offset + field_size])[0]
        parsed_values.append(field_value)
        offset += field_size

    return parsed_values


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
        print("Klient neinicializoval spojenie, uzatváram.")
        server_socket.close()
        return

def server_after_init(server_socket):
    while True:
        try:
            server_socket.settimeout(60)
            while True:
                received_info, address = server_socket.recvfrom(1500)
                flag = struct.unpack('!B', received_info[:1])[0]

                if flag == 2:
                    #TODO
                    print("keepalive on")
                    keepalive_packet = custom_packet(flag=2)
                    server_socket.sendto(bytes(keepalive_packet), address)

                elif flag == 3:
                    print("Bude sa prijímať správa.")
                    flag, number_of_fragments = parse_packet(flag, received_info)
                    data_process_server(server_socket, flag, number_of_fragments, "")

                elif flag == 4:
                    print("Bude sa prijímať súbor.")
                    flag, number_of_fragments, filename = parse_packet(flag, received_info)
                    data_process_server(server_socket, flag, number_of_fragments, filename)

        except socket.timeout:
            print("Klient neinicializoval komunikáciu, uzatváram.")
            server_socket.close()
            return

def data_process_server(server_socket, flag, number_of_fragments, file_name):
    return


def client():
    port = input("Zadajte port:")
    ip = input("Zadajte IP adresu:")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    destination = (ip, int(port))
    first_init_packet_cl = custom_packet(flag=1)
    client_socket.sendto(bytes(first_init_packet_cl), destination)
    received_info, address = client_socket.recvfrom(1500)

    flag = struct.unpack('!B', received_info[:1])[0]

    if flag == 1:
        print("Uspešná inicializácia spojenia na oboch stranách")
        client_after_init(client_socket)
    else:
        print("Nebolo inicializované spojenie, uzatváram")
        client_socket.close()
        return


def client_after_init(client_socket):
    return


def test():
    test_packet = custom_packet(flag=3, number_of_fragments=5, filename="exampe")

    # Call the __bytes__ method to get the byte representation
    packet_bytes = bytes(test_packet)
    packet_bytes = packet_bytes[:1] + b'\x00' + packet_bytes[1:]
    bytes_length = len(packet_bytes)
    filename_length = bytes_length - 5


    # Display the byte representation
    print("Byte representation:", packet_bytes)

    filename_field = str(filename_length) + "s"

    # Unpack the bytes dynamically
    fields = ['B', 'I', filename_field]  # Assuming 'B' for flag, 'BBB' for number_of_fragments

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
    print(f"FiLename of Fragments: {parsed_values[2].decode('utf-8')}")


if __name__ == "__main__":
    print("menu:")
    user_input = input("Zadaj server/klient")
    if user_input == "server":
        server()
    elif user_input == "klient":
        client()
    elif user_input == "test":
        test()