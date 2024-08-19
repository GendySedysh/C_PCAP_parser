CC = gcc

NAME = pcap_parser

SRC = src/main.c

OBJ = $(SRC:.c=.o)

all	:$(NAME)

$(NAME)	:$(OBJ)
	$(CC) -o $(NAME) $(OBJ) -lpcap
clean	:
	rm -f ./src/*.o

fclean	: clean
	rm -f pcap_parser

re	: clean all