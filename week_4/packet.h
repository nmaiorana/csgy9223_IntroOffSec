
enum op_codes : char
{
    BEGINNING = 0x0,
    COUNTLETTERS = 0x1,
    ENDING = 0x2
};

struct operation_struct
{
    enum op_codes op_code;
    char len;
    char word[0xf];
};

struct packet
{
    char packet_len;
    char checksum_val;
    struct operation_struct operation[0x1f];
};

struct current_op
{
    char packet_len;
    char word[0x1f];
    int checksum;
};

struct global_state_struct
{
    char count;
    char letter[0x1a];
};

struct strings
{
    char word[0xf];
};