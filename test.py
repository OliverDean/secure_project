def decode(message_file):
    """
    @brief Reads an encoded message from a text file and returns its decoded version as a string.
    
    @param message_file Path to the text file containing the encoded message.
    @return Decoded message as a string.
    """
    def read_file(file_path):
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
        except FileNotFoundError:
            raise FileNotFoundError("The file was not found.")
        except IOError:
            raise IOError("An error occurred while reading the file.")
        
        message_pairs = []
        for line in lines:
            try:
                num, word = line.strip().split()
                num = int(num)
                message_pairs.append((num, word))
            except ValueError:
                raise ValueError("Invalid format in file.")
        
        return message_pairs

    def build_pyramid(message_pairs):
        pyramid = {}
        for num, word in message_pairs:
            pyramid[num] = word
        return pyramid

    def decode_message(pyramid):
        decoded_words = []
        current_num = 1
        while current_num in pyramid:
            decoded_words.append(pyramid[current_num])
            current_num = (current_num * (current_num + 1)) // 2 + 1
        
        return ' '.join(decoded_words)
    
    message_pairs = read_file(message_file)
    pyramid = build_pyramid(message_pairs)
    decoded_message = decode_message(pyramid)
    
    return decoded_message

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python test.py <message_file>")
        sys.exit(1)
    
    message_file = sys.argv[1]
    try:
        print(decode(message_file))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
