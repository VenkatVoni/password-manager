import hashlib
import os
import pickle

no_itr = 100000
key_file = 'kk.bin'
info_file = 'info.bin'
message = '''
1.Add more passwords
2.Access passwords
3.Exit
'''


def write(name, lis, mode="w"):
    if mode == "a":
        with open(name, "ab") as f:
            pickle.dump(lis, f)
    elif mode == "w":
        with open(name, "wb") as f:
            pickle.dump(lis, f)
    else:
        raise ValueError("Invalid mode")


def read(name):
    with open(name, 'rb') as f:
        return pickle.load(f)


def read_till(name, username):
    try:
        f = open(name, 'rb')
        while True:
            x = pickle.load(f)
            if x[0] == username:
                return x
    except EOFError:
        return 0


def key_salt(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        no_itr
    )
    return key, salt


def encode(dat):
    return ''.join([chr(ord(i) + 3) for i in dat])


def decode(dat):
    return ''.join([chr(ord(i) - 3) for i in dat])


def main():
    if not os.path.exists(key_file):
        print("Setting up your master password")
        passwd = input("Enter the master password : ")
        write('kk.bin', key_salt(passwd))
        print('Master password is set')
    if not os.path.exists(info_file):
        with open(info_file, 'w') as f:
            pass
    usr_pw = input("Enter master password :")
    key, salt = read(key_file)
    usr_hash = hashlib.pbkdf2_hmac('sha256', usr_pw.encode('utf-8'), salt, no_itr)
    if key == usr_hash:
        while True:
            print(message)
            choice = int(input())
            if choice == 1:
                username = input("Enter the username : ")
                password = input("Enter its password : ")
                write(info_file, (encode(username), encode(password)), 'a')
                print("Password stored")
            elif choice == 2:
                user_check = encode(input("Enter the username for which you want password : "))
                pass_wd = decode(str(read_till(info_file, user_check)[1]))
                if pass_wd != "+":
                    print("The password for it is ", pass_wd)
                else:
                    print("Username not found")
            else:
                break
    else:
        print("Wrong password . Access denied")


if __name__ == '__main__':
    main()
