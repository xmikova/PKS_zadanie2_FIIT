# Zadanie 2: komunikácia s využitím UDP protokolu
# PKS - ZS 2023/2024
# Autor: Petra Miková

import copy
import math
import os
import random
import socket
import struct
import threading
import time
import binascii

#Globálne premenné pre keepalive
keepalive_event = threading.Event()
keepalive_event.set()

#Trieda custom_packet, kde si udržiavam všetky časti hlavičky a taktiež obsahuje funkciu, ktorá celý jej content dá do
#bitovej podoby na posielanie
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

#Funkcia na rozparsovanie bitov priajtého packetu podľa toho, o aký packet ide
def parse_packet(flag, received_info):
    if flag == 3:  #Textová sprava
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]

        fields = ['B', 'I']
        parsed_values = unpack_bytes(fields, packet_bytes)

        flag = parsed_values[0]
        number_of_fragments = parsed_values[1]

        return flag, number_of_fragments

    elif flag == 4:  #Súbor
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

    if flag == "data": #Packet s dátami
        packet_bytes = b'\x00' + received_info[:7]
        data = received_info[7:]

        fields = ['I', 'I']
        parsed_values = unpack_bytes(fields, packet_bytes)

        fragment_order = parsed_values[0]
        crc = parsed_values[1]

        return fragment_order, crc, data

    if flag == "data_server": #Packet s ACK/NACK od servera
        packet_bytes = received_info[:1] + b'\x00' + received_info[1:]

        fields = ['B', 'I']
        parsed_values = unpack_bytes(fields, packet_bytes)

        flag = parsed_values[0]
        fragment_order = parsed_values[1]

        return flag, fragment_order

#Pomocná funkcia pre funkciu parsovania bytov
def unpack_bytes(fields, packet_bytes):
    offset = 0
    parsed_values = []

    for field_format in fields:
        field_size = struct.calcsize(field_format)
        field_value = struct.unpack('!' + field_format, packet_bytes[offset:offset + field_size])[0]
        parsed_values.append(field_value)
        offset += field_size

    return parsed_values


#Jednoduchý check pre processing dát na server side kde sa kontroluje či je CRC správne
def is_fragment_correct(crc, data):
    recalculated_crc = binascii.crc32(data) & 0xFFFFFFFF
    return recalculated_crc == crc

#Funkcia pre udržiavanie sppojenia pomocou keepalive každých 5 sekúnd využivajúca thread
def send_keepalive(client_socket, address):
    global keepalive_event

    while keepalive_event.is_set():
        keepalive_packet = custom_packet(flag=2)
        client_socket.sendto(bytes(keepalive_packet), address)

        try:
            client_socket.settimeout(5)
            received_info, address = client_socket.recvfrom(1500)
        except (socket.timeout, ConnectionResetError):
            if not keepalive_event.is_set():
                return
            print("Žiadna odpoveď servera na keepalive. Spojenie uzavreté.")
            keepalive_event.clear()
            return

        flag = struct.unpack('!B', received_info[:1])[0]

        if flag == 2:
            pass
        elif flag == 9: #Taktiež sa tu handluje ak náhodou server namiesto keepalive odošle packet že explicitne končí
            print("Server skončil. Spojenie uzavreté.")
            keepalive_event.clear()
            client_socket.close()
            return
        else:
            print("Neočakávaná odpoveď na keepalive. Spojenie uzavreté.")
            keepalive_event.clear()
            return

        time.sleep(5)

# --------------------------------------- SERVER SIDE --------------------------------------------------
#Prvotná funckia pre server kde sa zadá port a establishuje sa spojenie
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
        server_after_init(server_socket, address)

    except OSError as e:
        if isinstance(e, socket.timeout):
            print("Nebol prijatý inicializačný packet od klienta, uzatváram spojenie.")
            server_socket.close()
            exit(0)
        else:
            print(f"OSError: {e}")


#Sem server pokračuje ak bolo správne nadviazané spojenie
def server_after_init(server_socket, address):
    while True:
        try:
            choice = input("Chcete skončiť? (zadajte exit): ")
            server_socket.settimeout(60)
            #Prijímajú sa packety a vykonáva sa akcia podľa flagu
            while True:
                received_info, address = server_socket.recvfrom(1500)
                flag = struct.unpack('!B', received_info[:1])[0]

                if choice == "exit":
                    exit_packet = custom_packet(flag=9)
                    server_socket.sendto(bytes(exit_packet), address)
                    server_socket.close()
                else:
                    if flag == 2:
                        print("Keepalive odoslané klientovi.")
                        keepalive_packet = custom_packet(flag=2)
                        server_socket.sendto(bytes(keepalive_packet), address)

                    elif flag == 3:
                        print("Bude sa prijímať správa.")
                        flag, number_of_fragments = parse_packet(flag, received_info)
                        data_process_server(server_socket, number_of_fragments, "")
                        break

                    elif flag == 4:
                        print("Bude sa prijímať súbor.")
                        flag, number_of_fragments, filename = parse_packet(flag, received_info)
                        data_process_server(server_socket, number_of_fragments, filename)
                        break

                    if flag == 8:
                        print("Klient si vyžiadal zmenu rolí.")
                        switch_agreed_packet = custom_packet(flag=8)
                        choice = input("Súhlasite so zmenou? (A/N): ")
                        if choice == "A":
                            print("Aktuálna rola: KLIENT")
                            server_socket.sendto(bytes(switch_agreed_packet), address)
                            client_after_init(server_socket,address)
                            return
                        elif choice == "N":
                            print("Aktuálna rola: SERVER")

                    elif flag == 9:
                        print("Klient skončil.")
                        server_socket.close()
                        exit(0)

        except socket.timeout:
            print("Klient nekomunikuje, uzatváram spojenie.")
            server_socket.close()
            exit(0)

#Funkcia kde sa vykonáva prenos dát na strane servera, prijímajú sa fragmenty a odosiela sa ACK/NACK
def data_process_server(server_socket, number_of_fragments, file_name):
    fragments_received = set()
    reconstructed_data = []
    isDone = False

    while len(fragments_received) < number_of_fragments:
        try:
            server_socket.settimeout(60)
            received_info, address = server_socket.recvfrom(1500)
            fragment_order, crc, fragment_data = parse_packet("data", received_info)
            correct_crc = is_fragment_correct(crc, struct.pack('!I', fragment_order) + fragment_data)

            if correct_crc:
                fragments_received.add(fragment_order)
                reconstructed_data.append([fragment_order, fragment_data])
                ack_packet = custom_packet(flag=5, fragment_order=fragment_order)
                server_socket.sendto(bytes(ack_packet), address)
                print(f"Prijal sa fragment: {fragment_order}")
            else:
                nack_packet = custom_packet(flag=6, fragment_order=fragment_order)
                server_socket.sendto(bytes(nack_packet), address)
                print(f"Prijal sa chybný fragment, vypýtaný znova: {fragment_order}.")

        except socket.timeout:
            print("Timeout čakania za fragmentami, klient nekomunikuje.")
            server_socket.close()
            exit(0)

    received_info, address = server_socket.recvfrom(1500)
    flag = struct.unpack('!B', received_info[:1])[0]

    if flag == 7:
        isDone = True

    #Ak sa skončil prenos úspešne a máme všetky fragmenty
    if isDone:
        sorted_data = sorted(reconstructed_data, key=lambda x: x[0])
        concatenated_data = b''.join(data[1] for data in sorted_data)

        if file_name == "":  #Textová správa
            print(f"Prijala sa textová správa: {concatenated_data.decode('utf-8')}")

        else: #Súbor
            filename = os.path.basename(file_name)
            save_path = input("Zadaj cestu kam chceš uložiť súbor (stlač Enter pre defaultne uloženie do Downloads): ").strip()

            if not save_path:
                save_path = os.path.join(os.path.expanduser('~'), 'Downloads')

            with open(os.path.join(save_path, filename), 'wb') as file:
                file.write(concatenated_data)
            print(f"Súbor prijatý a uložený ako: {os.path.join(save_path, filename)}")

        #Možnosť pre server vykonať switch alebo pokračovať
        choice = input("Chcete pokračovať ako server alebo vykonať switch? (pokr/switch): ")
        if choice == "pokr":
            final_packet = custom_packet(flag=7, fragment_order=fragment_order)
            server_socket.sendto(bytes(final_packet), address)
        elif choice == "switch":
            final_packet = custom_packet(flag=8, fragment_order=fragment_order)
            server_socket.sendto(bytes(final_packet), address)
            print("Čaká sa za spätnou väzbou od klienta...")
            try:
                received_info, address = server_socket.recvfrom(1500)
                flag = struct.unpack('!B', received_info[:1])[0]
                if flag == 8:
                    print("Aktuálna rola: KLIENT")
                    client_after_init(server_socket, address)
                    return
                else:
                    print("Aktuálna rola: SERVER")
                    keepalive_packet = custom_packet(flag=2)
                    server_socket.sendto(bytes(keepalive_packet), address)
                    print("Keepalive odoslané klientovi.")
                    return
            except socket.timeout:
                print("Timeout čakania za odpoveďou klienta.")
                exit(0)
                return

# --------------------------------------- CLIENT SIDE --------------------------------------------------
#Prvotná funckia pre klienta kde sa zadá port a IP a establishuje sa spojenie
def client():
    port = input("Zadajte port:")
    ip = input("Zadajte IP adresu:")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    destination = (ip, int(port))
    first_init_packet_cl = custom_packet(flag=1)
    client_socket.sendto(bytes(first_init_packet_cl), destination)
    try:
        received_info, address = client_socket.recvfrom(1500)

        flag = struct.unpack('!B', received_info[:1])[0]

        if flag == 1:
            print("Uspešná inicializácia spojenia na oboch stranách")
            client_after_init(client_socket, address)
        else:
            print("Nebolo inicializované spojenie, uzatváram.")
            client_socket.close()
            return

    except socket.timeout:
        print("Nebolo inicializované spojenie, uzatváram.")
        client_socket.close()

#Sem klient prechádza po úspešnom spojení a vyberá si z možností odoslať správu/súbor, vykonať switch alebo skončiť
#Taktiež sa začína keepalive thread
def client_after_init(client_socket, address):
    global keepalive_event

    #Thread pre keepalive
    keepalive_thread = threading.Thread(target=send_keepalive, args=(client_socket, address))
    keepalive_thread.start()

    while True:
        choice = int(input("Zadajte možnosť, 3 pre poslanie spravy, 4 pre poslanie suboru, 5 pre switch, 6 pre exit"))
        if choice == 3 or choice == 4:  #Prenos dát
            try:
                # Textová správa
                    keepalive_event.clear()  #Počas prenosu dát vypnuté keepalive

                    if choice == 3:
                        data_process_client(client_socket, address, "text")

                    elif choice == 4:
                        data_process_client(client_socket, address, "file")

            except Exception as e:
                print(f"Nastala neočakávaná chyba: {e}")

            finally: #Pustíme po prenose naspäť keepalive
                keepalive_event.set()
                keepalive_thread = threading.Thread(target=send_keepalive, args=(client_socket, address))
                keepalive_thread.start()

        elif choice == 5:  #Switch
            switch_packet = custom_packet(flag=8)
            client_socket.sendto(bytes(switch_packet), address)

            try:
                received_info, server_address = client_socket.recvfrom(1500)
                flag = struct.unpack('!B', received_info[:1])[0]

                if flag == 8:
                    print("Aktuálna rola: SERVER")
                    keepalive_event.clear()
                    server_after_init(client_socket,address)
                    return
                else:
                    print("Aktuálna rola: KLIENT")
                    continue

            except socket.timeout:
                print("Timeout čakania za odpoveďou servera.")
                continue

        elif choice == 6: #Explicitne ukončenie
            finish_packet = custom_packet(flag=9)
            client_socket.sendto(bytes(finish_packet), address)
            keepalive_event.clear()
            client_socket.close()
            return

#Funkcia kde sa vypočíta počet fragmentov na odoslanie zo zadanej veľkosti a pošle sa inicializačný packet o prenose dát
def data_process_client(client_socket, address, msg_type):
    how_many_wrong = 0

    fragment_size = int(input("Zadajte velkost jedneho fragmentu (do 1461 B):"))

    while fragment_size > 1461 or fragment_size < 0:
        print("Nesprávne zadaná veľkosť fragmentu, prosím ešte raz:")
        fragment_size = int(input("Zadajte velkost jedneho fragmentu (do 1461 B):"))

    choice_wrong = input("Chcete posielat aj zlé packety? (A/N):")

    if choice_wrong == "A":
        how_many_wrong = int(input("Koľko zlých packetov chcete odoslať?: "))


    if msg_type == "text":
        message = input("Zadajte telo správy:")
        message_size = len(message)
        num_of_fragments_message = math.ceil(message_size / fragment_size)
        message_init_packet = custom_packet(flag=3, number_of_fragments=num_of_fragments_message)
        client_socket.sendto(bytes(message_init_packet),address)
        fragments = [i for i in range(num_of_fragments_message)]
        print("Ide sa odosielať ", num_of_fragments_message,"fragmentov o veľkosti ",fragment_size,"B")
        selective_repeat_arq(client_socket,fragments,fragment_size, address, message, "text", how_many_wrong)
    elif msg_type == "file":
        file_path = input("Zadajte cestu k súboru:")

        try:
            print("Prichádza súbor: ", file_path)
            with open(file_path, 'rb') as file:
                file_to_be_send = file.read()
                file_size = len(file_to_be_send)
                print("Lokácia súboru: ", os.path.abspath(file_path))
                num_of_fragments_file = math.ceil(file_size / fragment_size)
                file_init_packet = custom_packet(flag=4, number_of_fragments=num_of_fragments_file, filename=file_path)
                client_socket.sendto(bytes(file_init_packet), address)
                fragments = [i for i in range(num_of_fragments_file)]
                print("Ide sa odosielať ", num_of_fragments_file, "fragmentov o veľkosti ", fragment_size, "B")
                selective_repeat_arq(client_socket,fragments,fragment_size, address, file_to_be_send, "file", how_many_wrong)

        except FileNotFoundError:
            print(f"Súbor '{file_path}' sa nenašiel.")

#Samotný prenos dát pomocou Selective Repeat s veľkosťou okna 4, ktorá sa samozrejme prispôsobí ak máme menej packetov.
def selective_repeat_arq(client_socket, fragments, fragment_size, address, user_data, data_type, how_many_wrong):
    window_size = min(4, len(fragments))
    start_index = 0
    end_index = start_index + fragment_size
    frags_to_be_send = copy.deepcopy(fragments)
    frags_to_be_acked = copy.deepcopy(fragments)

    wrong_packets = random.sample(fragments, how_many_wrong)

    #Prvotne odoslanie n fragmentov z okna
    for i in range(window_size):
        if data_type == "text":
            fragment_data = (user_data[start_index:end_index]).encode('utf-8')
        elif data_type == "file":
            fragment_data = (user_data[start_index:end_index])

        #Ak chceme odoslať chybný fragment modifikujeme CRC
        if i in wrong_packets:
            crc = binascii.crc32(struct.pack('!I', i) + fragment_data) & 0xFFFFFFFF
            crc = int(crc / 2)
            wrong_packets.remove(i)
        else:
            crc = binascii.crc32(struct.pack('!I', i) + fragment_data) & 0xFFFFFFFF

        start_index = end_index
        end_index = start_index + fragment_size
        fragment_packet = custom_packet(fragment_order=i, crc=crc, data=fragment_data)
        client_socket.sendto(bytes(fragment_packet), address)
        print(f"Odoslal sa fragment: {i}")
        frags_to_be_send.remove(i)

    start_index = window_size * fragment_size
    end_index = start_index + fragment_size

    #Po odoslaní fragmentov z okna sa začína prijatie ACK/NACK pre prvý odoslaný z tohto okna a posúva sa okno
    try:
        client_socket.settimeout(15)
        while len(frags_to_be_acked) != 0:
            try:
                client_socket.settimeout(15)
                #Vykonáva sa pokiaľ ešte stále treba odosiealať packety
                while len(frags_to_be_send) != 0:
                    i = frags_to_be_send[0]
                    received_info, address = client_socket.recvfrom(1500)
                    flag, fragment_order = parse_packet("data_server", received_info)
                    start_index, end_index, frags_to_be_send = flag_check(client_socket, flag, fragment_order,address, i,
                                                                          frags_to_be_send, frags_to_be_acked, user_data, start_index,
                                                                          end_index, fragment_size, data_type, wrong_packets)
            except socket.timeout:
                print("Spojenie sa stratilo.")
                exit(1)

            #Tu sa už len prijímajú ACK/NACK ak sa poslali všetky packety
            received_info, address = client_socket.recvfrom(1500)
            flag, fragment_order = parse_packet("data_server", received_info)
            if flag == 5:
                print(f"Prijaté ACK: {fragment_order}")
                frags_to_be_acked.remove(fragment_order)

            elif flag == 6:
                print(f"Prijaté NACK, vykoná sa retransmit: {fragment_order}")
                frags_to_be_send.insert(0, fragment_order)
                if len(frags_to_be_acked) == 1 and frags_to_be_acked[0] == fragment_order:
                    start_index = frags_to_be_send[0] * fragment_size
                    end_index = start_index + fragment_size
                    frags_to_be_acked.remove(fragment_order)
                    if data_type == "text":
                        fragment_data = (user_data[start_index:end_index]).encode('utf-8')
                    elif data_type == "file":
                        fragment_data = (user_data[start_index:end_index])

                    crc = binascii.crc32(fragment_data) & 0xFFFFFFFF

                    fragment_packet = custom_packet(fragment_order=i, crc=crc, data=fragment_data)
                    client_socket.sendto(bytes(fragment_packet), address)
                    print(f"Odoslal sa fragment: {i}")
                    frags_to_be_send.remove(i)
                else:
                    received_info, address = client_socket.recvfrom(1500)
                    flag, fragment_order = parse_packet("data_server", received_info)
                    start_index = frags_to_be_send[0] * fragment_size
                    end_index = start_index + fragment_size
                    start_index, end_index, frags_to_be_send = flag_check(client_socket, flag, fragment_order, address,
                                                                          frags_to_be_send[0], frags_to_be_send,
                                                                          frags_to_be_acked, user_data, start_index,
                                                                          end_index, fragment_size, data_type, wrong_packets,
                                                                          )
    except socket.timeout:
        print("Spojenie sa stratilo.")
        exit(1)

    #Ukončenie odosielania a čakanie za rozhodnutím servera
    final_packet = custom_packet(flag=7)
    client_socket.sendto(bytes(final_packet), address)
    try:
        print("Čaká sa za spätnou väzbou servera...")
        client_socket.settimeout(60)
        received_info, address = client_socket.recvfrom(1500)
        flag = struct.unpack('!B', received_info[:1])[0]

        if flag == 7:
            print("Prenos dát pomocou Selective Repeat ARQ hotový.")
            return
        elif flag == 8:
            print("Prenos dát hotový, server si chce vymeniť rolu.")
            switch_agreed_packet = custom_packet(flag=8)
            choice = input("Súhlasite so zmenou? (A/N): ")
            if choice == "A":
                client_socket.sendto(bytes(switch_agreed_packet), address)
                print("Aktuálna rola: SERVER")
                server_after_init(client_socket, address)
                return
            elif choice == "N":
                print("Aktuálna rola: KLIENT")
                return

    except socket.timeout:
        print("Timeout čakania za finálnym ACKom")

    finally:
        client_socket.settimeout(None)


#Funkcia kde sa kontroliuje prijatý packet od servera ako response na odoslané fragmenty, ak sa prijem NACK vykonáva
#sa retransmission
def flag_check(client_socket, flag, fragment_order, address, i, frags_to_be_send, frags_to_be_acked, user_data, start_index,
               end_index, fragment_size, data_type, wrong_packets):
    if flag == 5:
        print(f"Prijatý ACK: {fragment_order}")
        if fragment_order in frags_to_be_acked:
            frags_to_be_acked.remove(fragment_order)
        if data_type == "text":
            fragment_data = (user_data[start_index:end_index]).encode('utf-8')
        elif data_type == "file":
            fragment_data = (user_data[start_index:end_index])

        if i in wrong_packets:
            crc = binascii.crc32(struct.pack('!I', i) + fragment_data) & 0xFFFFFFFF
            crc = int(crc / 2)
            wrong_packets.remove(i)
        else:
            crc = binascii.crc32(struct.pack('!I', i) + fragment_data) & 0xFFFFFFFF

        fragment_packet = custom_packet(fragment_order=i, crc=crc, data=fragment_data)
        client_socket.sendto(bytes(fragment_packet), address)
        print(f"Odoslal sa fragment: {i}")
        frags_to_be_send.remove(i)
        if len(frags_to_be_send) != 0:
            start_index = frags_to_be_send[0] * fragment_size
            end_index = start_index + fragment_size
    elif flag == 6:
        print(f"Prijatý NACK, vykoná sa retransmit: {fragment_order}")
        frags_to_be_send.insert(0, fragment_order)
        if len(frags_to_be_acked) != 0:
            try:
                received_info, address = client_socket.recvfrom(1500)
                flag, fragment_order = parse_packet("data_server", received_info)
                if frags_to_be_acked[1] != fragment_order:
                    frags_to_be_acked.remove(fragment_order)
            except socket.timeout:
                if data_type == "text":
                    fragment_data = (user_data[start_index:end_index]).encode('utf-8')
                elif data_type == "file":
                    fragment_data = (user_data[start_index:end_index])

                crc = binascii.crc32(struct.pack('!I', i) + fragment_data) & 0xFFFFFFFF

                fragment_packet = custom_packet(fragment_order=i, crc=crc, data=fragment_data)
                client_socket.sendto(bytes(fragment_packet), address)
                print(f"Odoslal sa fragment: {i}")
                frags_to_be_send.remove(i)
                if len(frags_to_be_send) != 0:
                    start_index = frags_to_be_send[0] * fragment_size
                    end_index = start_index + fragment_size
                return start_index, end_index, frags_to_be_send
        i = frags_to_be_send[0]
        start_index = i * fragment_size
        end_index = start_index + fragment_size
        start_index, end_index, frags_to_be_send = flag_check(client_socket, flag, fragment_order, address, i,
                                                              frags_to_be_send, frags_to_be_acked,  user_data,
                                                              start_index, end_index, fragment_size,  data_type,
                                                              wrong_packets)

    return start_index, end_index, frags_to_be_send

#Menu pre užívateľa kde si vyberá či chce byť server/klient
if __name__ == "__main__":
    print("*----------------------------------------------------------------------------*")
    print("|                  Komunikácia s využitím UDP protokolu                      |")
    print("|                           Autor: Petra Miková                              |")
    print("*----------------------------------------------------------------------------*")
    print("Menu:")
    user_input = input("Zadajte rolu (server/klient):")

    while user_input not in ["server", "klient"]:
        print("Nesprávny vstup. Prosím zadajte znova.")
        user_input = input("Zadajte rolu (server/klient):")

    if user_input == "server":
        server()
    elif user_input == "klient":
        client()