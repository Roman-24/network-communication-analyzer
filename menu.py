
import os

def menu(pcap_files_paths):
    print("Pre ukoncenie programu napis: e")
    print("Pre vlastnu cestu k suboru zadaj: 0")
    print(f"Pre vyber cisla suboru od 1 do {len(pcap_files_paths)} ")

    user_input = input()

    if (user_input == "e"):
        print("Exit..")
        exit()

    user_input = int(user_input)

    if(user_input == 0):
        print("Zadaj relativnu cestu k suboru: ")
        user_path = input()
        return os.path.join(os.path.dirname(__file__), user_path)

    if(user_input > 0 and user_input < len(pcap_files_paths)):
        return os.path.join(os.path.dirname(__file__), (pcap_files_paths[user_input - 1])[:-1])
