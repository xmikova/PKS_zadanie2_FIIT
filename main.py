import copy
import math
import os
import socket
import struct
import threading
import time


class custom_packet:
    def __init__(self, flag=None, number_of_fragments=None, fragment_order=None, crc=None,
                 data=None, filename=None):
        self.flag = flag
        self.number_of_fragments = number_of_fragments
        self.fragment_order = fragment_order
        self.crc = crc
        self.data = data
        self.filename = filename

    def __bytes__(self):
        flag_bytes = struct.pack('!B', self.flag) if self.flag is not None else b''
        number_of_fragments_bytes = struct.pack('!BBB', (self.number_of_fragments >> 16) & 0xFF,
                                                (self.number_of_fragments >> 8) & 0xFF,
                                                self.number_of_fragments & 0xFF) if self.number_of_fragments is not None else b''
        fragment_order_bytes = struct.pack('!BBB', (self.fragment_order >> 16) & 0xFF,
                                           (self.fragment_order >> 8) & 0xFF,
                                           self.fragment_order & 0xFF) if self.fragment_order is not None else b''
        crc_bytes = struct.pack('!I', self.crc) if self.crc is not None else b''
        filename_bytes = self.filename.encode('utf-8') if self.filename is not None else b''
        data_bytes = self.data if self.data is not None else b''

        return flag_bytes + number_of_fragments_bytes + fragment_order_bytes + crc_bytes + filename_bytes + data_bytes


def parse_packet(flag, received_info):  # TODO
    if flag == 3:  # textova sprava
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]

        fields = ['B', 'I']
        parsed_values = unpack_bytes(fields, packet_bytes)

        flag = parsed_values[0]
        number_of_fragments = parsed_values[1]

        return flag, number_of_fragments

    elif flag == 4:  # subor
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]
        bytes_length = len(packet_bytes)
        filename_length = bytes_length - 5
        filename_field = str(filename_length) + "s"

        fields = ['B', 'I', filename_field]
        parsed_values = unpack_bytes(fields, packet_bytes)

        flag = parsed_values[0]
        number_of_fragments = parsed_values[1]
        filename = parsed_values[2].decode('utf-8')

        return flag, number_of_fragments, filename

    if flag == "data":
        packet_bytes = b'\x00' + received_info[:3]
        file = received_info[3:]

        fields = ['I']
        parsed_values = unpack_bytes(fields, packet_bytes)

        fragment_order = parsed_values[0]

        return fragment_order, file

    if flag == "data_server":
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]

        fields = ['B', 'I']
        parsed_values = unpack_bytes(fields, packet_bytes)

        flag = parsed_values[0]
        fragment_order = parsed_values[1]

        return flag, fragment_order

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


def is_fragment_correct(fragment_data):
    # You need to implement the logic to check if the fragment is correct or corrupted
    # For simplicity, let's assume all fragments are correct
    return True


def send_keepalive(client_socket, address):
    global keepalive_active

    while keepalive_active.is_set():
        keepalive_packet = custom_packet(flag=2)
        client_socket.sendto(bytes(keepalive_packet), address)

        try:
            client_socket.settimeout(2)
            received_info, address = client_socket.recvfrom(1500)
        except (socket.timeout, ConnectionResetError):
            if not keepalive_active.is_set():
                return
            print("Žiadna odpoveď servera na keepalive. Spojenie uzavreté.")
            keepalive_active.clear()
            return

        flag = struct.unpack('!B', received_info[:1])[0]

        if flag == 2:
            print("Prijaté keepalive od servera")
        else:
            print("Neočakávaná odpoveď na keepalive. Spojenie uzavreté.")
            keepalive_active.clear()
            return

        time.sleep(5)


# ---------------------------------------------------------------------------------------------------------------------
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
                    print("Keepalive odoslané klientovi.")
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
    fragments_received = set()
    reconstructed_data = []
    isDone = False

    while len(fragments_received) < number_of_fragments:
        try:
            server_socket.settimeout(60)
            received_info, address = server_socket.recvfrom(1500)
            fragment_order, fragment_data = parse_packet("data", received_info)
            #kkt = is_fragment_correct(fragment_data)  # Implement your own logic
            kkt = True

            if kkt:
                fragments_received.add(fragment_order)
                reconstructed_data.append([fragment_order, fragment_data])
                ack_packet = custom_packet(flag=5, fragment_order=fragment_order)
                server_socket.sendto(bytes(ack_packet), address)
                print(f"Received fragment: {fragment_order} with data {fragment_data}")
            else:
                nack_packet = custom_packet(flag=6, fragment_order=fragment_order)
                server_socket.sendto(bytes(nack_packet), address)
        except socket.timeout:
            print("Timeout waiting for fragments. Reconstructing data...")

    received_info, address = server_socket.recvfrom(1500)
    flag = struct.unpack('!B', received_info[:1])[0]

    if flag == 7:
        isDone = True

    if isDone:
        #  Sort the reconstructed_data based on fragment_order
        sorted_data = sorted(reconstructed_data, key=lambda x: x[0])

        # Concatenate the fragment_data into a byte string
        concatenated_data = b''.join(data[1] for data in sorted_data)

        # Now, you can process the concatenated_data based on the original data type (text or file)
        if file_name == "":  # Text message
            print(f"Received text message: {concatenated_data.decode('utf-8')}")

        else:
            # Save the reconstructed file data to the specified file_name
            with open(file_name, 'wb') as file:
                file.write(concatenated_data)
            print(f"File received and saved as: {file_name}")


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
        client_after_init(client_socket, address)
    else:
        print("Nebolo inicializované spojenie, uzatváram")
        client_socket.close()
        return


def client_after_init(client_socket, address):
    global keepalive_active

    # Thread pre keepalive
    keepalive_active = threading.Event()
    keepalive_active.set()  # Start with keepalive active
    keepalive_thread = threading.Thread(
        target=send_keepalive, args=(client_socket, address)
    )

    choice = int(input("Zadajte možnosť, 3 pre poslanie spravy, 4 pre poslanie suboru"))
    keepalive_thread.start()

    # Prenos dát
    try:
        # Textová správa
        if choice == 3 or choice == 4:

            keepalive_active.clear()

            if choice == 3:
                data_process_client(client_socket, address, "text")
            # TODO: Continue with data transfer logic
            elif choice == 4:
                data_process_client(client_socket, address, "file")
            # Example: Turn on keepalive after data transfer
            if choice == 5:  # toto dame ze ak success tak sa znovapusti
                keepalive_active.set()

    except KeyboardInterrupt:
        print("Exiting...")
        keepalive_active.set()  # Set the event to allow the keepalive thread to exit
        keepalive_thread.join()

    return


def data_process_client(client_socket, address, msg_type):
    fragment_size = int(input("Zadajte velkost jedneho fragmentu (do 1461 B):"))

    # TODO check na velkost fragmentu od uzivatela
    # TODO wrong packets

    if msg_type == "text":
        message = input("Zadajte telo správy:")
        message_size = len(message)
        num_of_fragments_message = math.ceil(message_size / fragment_size)
        message_init_packet = custom_packet(flag=3, number_of_fragments=num_of_fragments_message)
        client_socket.sendto(bytes(message_init_packet),address)
        fragments = [i for i in range(num_of_fragments_message)]
        selective_repeat_arq(client_socket,fragments,fragment_size, address, message, "text")
    elif msg_type == "file":
        file_path = input("Zadajte cestu k súboru:")

        try:
            with open(file_path, 'rb') as file:
                file_to_be_send = file.read()
                file_size = len(file_to_be_send)
                print("Lokácia súboru: ", os.path.abspath(file_path))
                num_of_fragments_file = math.ceil(file_size / fragment_size)
                file_init_packet = custom_packet(flag=4, number_of_fragments=num_of_fragments_file, filename=file_path)
                client_socket.sendto(bytes(file_init_packet), address)
                fragments = [i for i in range(num_of_fragments_file)]
                selective_repeat_arq(client_socket,fragments,fragment_size, address, file_to_be_send, "file")

        except FileNotFoundError:
            print(f"Súbor '{file_path}' sa nenašiel.")
        return


def selective_repeat_arq(client_socket, fragments, fragment_size, address, user_data, data_type, corruption_rate=0.1):
    window_size = min(4, len(fragments))
    start_index = 0
    end_index = start_index + fragment_size
    frags_to_be_send = copy.deepcopy(fragments)
    frags_to_be_acked = copy.deepcopy(fragments)

    #Prvotne odoslanie n fragmentov z okna
    for i in range(window_size):
        if data_type == "text":
            fragment_data = (user_data[start_index:end_index]).encode('utf-8')
        elif data_type == "file":
            fragment_data = (user_data[start_index:end_index])
        start_index = end_index
        end_index = start_index + fragment_size
        fragment_packet = custom_packet(fragment_order=i, data=fragment_data)
        client_socket.sendto(bytes(fragment_packet), address)
        print(f"Sent fragment: {i} with data: {fragment_data}")
        frags_to_be_send.remove(i)

    start_index = window_size * 2 + fragment_size + 1
    end_index = start_index + fragment_size

    while len(frags_to_be_acked) != 0:
        while len(frags_to_be_send) != 0:
            i = frags_to_be_send[0]
            received_info, address = client_socket.recvfrom(1500)
            flag, fragment_order = parse_packet("data_server", received_info)
            if fragment_order == frags_to_be_acked[0]:
                frags_to_be_acked.remove(fragment_order)

            start_index, end_index, frags_to_be_send = flag_check(client_socket, flag, fragment_order,address, i,
                                                                  frags_to_be_send, user_data, start_index,
                                                                  end_index, fragment_size, data_type)

        received_info, address = client_socket.recvfrom(1500)
        flag, fragment_order = parse_packet("data_server", received_info)
        if flag == 5:
            print(f"Received ACK: {fragment_order}")
            frags_to_be_acked.remove(fragment_order)

        elif flag == 6:
            print(f"Received NACK, gonna retransmit: {fragment_order}")
            frags_to_be_send.insert(0, fragment_order)
            received_info, address = client_socket.recvfrom(1500)
            flag, fragment_order = parse_packet("data_server", received_info)
            flag_check(client_socket, flag, fragment_order, address, frags_to_be_send[0], frags_to_be_send, user_data, start_index,
                       end_index, fragment_size, data_type)

    print("Selective Repeat ARQ completed.")
    final_packet = custom_packet(flag=7)
    client_socket.sendto(bytes(final_packet), address)

def flag_check(client_socket, flag, fragment_order, address, i, frags_to_be_send, user_data, start_index, end_index, fragment_size, data_type):
    if flag == 5:
        print(f"Received ACK: {fragment_order}")
        if data_type == "text":
            fragment_data = (user_data[start_index:end_index]).encode('utf-8')
        elif data_type == "file":
            fragment_data = (user_data[start_index:end_index])
        start_index = end_index
        end_index = start_index + fragment_size
        fragment_packet = custom_packet(fragment_order=i, data=fragment_data)
        client_socket.sendto(bytes(fragment_packet), address)
        print(f"Sent fragment: {i} with data: {fragment_data}")
        frags_to_be_send.remove(i)
    elif flag == 6:
        print(f"Received NACK, gonna retransmit: {fragment_order}")
        frags_to_be_send.insert(0, fragment_order)
        received_info, address = client_socket.recvfrom(1500)
        flag, fragment_order = parse_packet("data_server", received_info)
        flag_check(client_socket, flag, fragment_order, address, i, frags_to_be_send, user_data, start_index, end_index, fragment_size)

    return start_index, end_index, frags_to_be_send


def test():
    return

if __name__ == "__main__":
    print("menu:")
    user_input = input("Zadaj server/klient")
    if user_input == "server":
        server()
    elif user_input == "klient":
        client()
    elif user_input == "test":
        test()
