#include <stdio.h>
#include "AES.h"

int main()
{
	uint8_t state_matrix[4][4] = {0};
	char *plain_text = input_from__user();
	key_s *original_key = input_key_from_user();
	key_s *key_ptr = key_expansion(original_key, Rcon[0]);
	int i = 0, j = 0, k = 0, n = 0 ,m = 0;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			key_round[0].keys[i][j] = key_ptr->keys[i][j];
		}
	}
	for (k = 0; k < 9; k++)
	{
		key_ptr = key_expansion(&(key_round[k]), Rcon[k + 1]);
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				key_round[k + 1].keys[i][j] = key_ptr->keys[i][j];
			}
		}
	}
	while (plain_text[m] != '\0')
	{
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				state_matrix[i][j] = plain_text[n];
				n++;
			}
		}
		printf("PlainText is: \n");
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				printf("0x%02x\t",state_matrix[i][j]);
			}
			printf("\n");
		}

		state_s *state = initial_add_round(original_key, state_matrix);
		state_s *res = Encryption_rounds(state, &key_round[0]);
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				round_res[0].state[i][j] = res->state[i][j];
			}
		}
		for (k = 0; k < 8; k++)
		{
			res = Encryption_rounds(&round_res[k], &key_round[k + 1]);
			for (i = 0; i < 4; i++)
			{
				for (j = 0; j < 4; j++)
				{
					round_res[k + 1].state[i][j] = res->state[i][j];
				}
			}
		}

		state_s *encrypted_ptr = last_round(&round_res[8], &key_round[9]);
		state_s Encrypted_text;
		printf("Encrypted text:\n");
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				Encrypted_text.state[j][i] = encrypted_ptr->state[i][j];
				printf("0x%02x\t", Encrypted_text.state[j][i]);
			}
			printf("\n");
		}
		m = n + 1;
	}
}

key_s *input_key_from_user(void)
{
	uint8_t hex_value[16];
	static key_s user_key_input;
	uint8_t buffer[33];
	uint8_t i = 0, j;
	printf("Enter the secret key(16 bytes): \n");
	fgets(buffer, 33, stdin);
	while (i < 32)
	{
		if (buffer[i] >= '0' && buffer[i] <= '9')
			hex_value[i / 2] = (hex_value[i / 2] << 4) | (buffer[i] - '0');
		else if (buffer[i] >= 'A' && buffer[i] <= 'F')
			hex_value[i / 2] = (hex_value[i / 2] << 4) | (buffer[i] - 'A' + 10);
		else if (buffer[i] >= 'a' && buffer[i] <= 'f')
			hex_value[i / 2] = (hex_value[i / 2] << 4) | (buffer[i] - 'a' + 10);
		i++;
	}
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			user_key_input.keys[i][j] = hex_value[i * 4 + j];
		}
	}
	return &user_key_input;
}

char *input_from__user(void)
{
	static char user_input_str[size];
	size_t i = 0, n = 0;
	uint8_t N = 0;
	char c;
	printf("Enter the plaintext: \n");
	while ((c = getchar()) != '\n' && c != EOF)
	{
		user_input_str[i] = c;
		i++;
	}
	if (c == '\n')
	{
		user_input_str[i] = '\n';
	}
	n = i + 1; 
	uint8_t padding = 16 - (n % 16);
	++i;
	while (padding != 0 && N != padding)
	{
		user_input_str[i] = padding;
		++N;
		++i;
	}
	++i;
	user_input_str[i] = '\0';
	return user_input_str;
}
state_s *last_round(state_s *state, key_s *key_mat)
{
	static state_s result;
	uint8_t i, j, row, col;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			row = (state->state[i][j] & 0xF0);
			col = (state->state[i][j] & 0x0F);
			result.state[i][j] = (s_box[row >> 4][col]);
		}
	}
	uint8_t temp[4] = {0};
	temp[3] = result.state[0][1];
	for (i = 0; i < 3; i++)
	{
		temp[i] = result.state[i + 1][1];
	}
	for (i = 0; i < 4; i++)
	{
		result.state[i][1] = temp[i];

		temp[i] = 0;
	}

	temp[0] = result.state[2][2];
	temp[1] = result.state[3][2];
	temp[2] = result.state[0][2];
	temp[3] = result.state[1][2];
	for (i = 0; i < 4; i++)
	{
		result.state[i][2] = temp[i];

		temp[i] = 0;
	}

	temp[0] = result.state[3][3];
	temp[1] = result.state[0][3];
	temp[2] = result.state[1][3];
	temp[3] = result.state[2][3];
	for (i = 0; i < 4; i++)
	{
		result.state[i][3] = temp[i];

		temp[i] = 0;
	}
	for (i = 0; i < 4; i++)
	{

		for (j = 0; j < 4; j++)
		{

			result.state[i][j] = result.state[i][j] ^ key_mat->keys[i][j];
		}
	}
	return (&result);
}

key_s *key_expansion(key_s *original_key, uint8_t rc)
{
	static key_s key;
	uint8_t temp[4] = {0};
	uint8_t i, j;
	for (i = 0; i < 4; i++)
	{
		temp[i] = original_key->keys[3][i];
	}
	for (i = 0; i < 3; i++)
	{
		temp[i] = temp[i + 1];
	}
	temp[3] = original_key->keys[3][0];
	for (i = 0; i < 4; i++)
	{
		uint8_t row = (temp[i] & 0xF0);
		uint8_t col = (temp[i] & 0x0F);

		temp[i] = (s_box[(row >> 4)][col]);
	}
	uint8_t rc_mat[4] = {rc, 0x00, 0x00, 0x00};
	for (i = 0; i < 4; i++)
	{
		temp[i] = temp[i] ^ rc_mat[i];
	}
	for (i = 0; i < 4; i++)
	{
		temp[i] = temp[i] ^ original_key->keys[0][i];
		key.keys[0][i] = temp[i];
	}
	for (i = 0; i < 4; i++)
	{

		temp[i] = (original_key->keys[1][i] ^ temp[i]);

		key.keys[1][i] = temp[i];
	}
	for (i = 0; i < 4; i++)
	{
		temp[i] = (original_key->keys[2][i] ^ temp[i]);
		key.keys[2][i] = temp[i];
	}
	for (i = 0; i < 4; i++)
	{
		temp[i] = (original_key->keys[3][i] ^ temp[i]);
		key.keys[3][i] = temp[i];
	}

	return (&key);
}

state_s *initial_add_round(key_s *key_1, uint8_t state_mat[][4])
{
	int i, j;
	static state_s result;

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{

			result.state[i][j] = (key_1->keys[i][j] ^ state_mat[i][j]);
		}
	}
	return &result;
}

state_s *Encryption_rounds(state_s *state, key_s *key_mat)
{

	state_s result;
	uint8_t i, j, row, col, k, m = 0, n = 0;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			row = (state->state[i][j] & 0xF0);
			col = (state->state[i][j] & 0x0F);
			result.state[i][j] = (s_box[row >> 4][col]);
		}
	}

	uint8_t temp[4] = {0};
	temp[3] = result.state[0][1];
	for (i = 0; i < 3; i++)
	{
		temp[i] = result.state[i + 1][1];
	}
	for (i = 0; i < 4; i++)
	{
		result.state[i][1] = temp[i];

		temp[i] = 0;
	}

	temp[0] = result.state[2][2];
	temp[1] = result.state[3][2];
	temp[2] = result.state[0][2];
	temp[3] = result.state[1][2];
	for (i = 0; i < 4; i++)
	{
		result.state[i][2] = temp[i];

		temp[i] = 0;
	}

	temp[0] = result.state[3][3];
	temp[1] = result.state[0][3];
	temp[2] = result.state[1][3];
	temp[3] = result.state[2][3];
	for (i = 0; i < 4; i++)
	{
		result.state[i][3] = temp[i];

		temp[i] = 0;
	}

	multi_s multi_mat = {
		.index = {
			{0x2, 0x3, 0x1, 0x1},
			{0x1, 0x2, 0x3, 0x1},
			{0x1, 0x1, 0x2, 0x3},
			{0x3, 0x1, 0x1, 0x2}}};
	uint8_t transition_col[4][1] = {0};
	uint8_t intermediate_col[4][1] = {0};
	uint8_t intermediate_res[4][4] = {0};
	while (m < 4)
	{
		for (i = 0; i < 4; i++)
		{
			transition_col[i][0] = result.state[m][i];
		}

		uint8_t galois_multi_res[4][1] = {0};
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 1; j++)
			{
				for (k = 0; k < 4; k++)
				{
					if (multi_mat.index[i][k] == 0x1)
					{

						galois_multi_res[k][j] = transition_col[k][j];
					}

					if (multi_mat.index[i][k] == 0x2)
					{

						if (transition_col[k][j] >= 0x80)
						{
							uint8_t temp = 0;

							temp = transition_col[k][j] << 0x1;
							galois_multi_res[k][j] = temp ^ 0x1B;
						}
						else
						{

							galois_multi_res[k][j] = transition_col[k][j] << 0x1;
						}
					}
					if (multi_mat.index[i][k] == 0x3)
					{

						uint8_t temp, temp_1 = 0;
						temp = transition_col[k][j];
						if (transition_col[k][j] >= 0x80)
						{

							temp_1 = transition_col[k][j] << 0x1;
							galois_multi_res[k][j] = temp_1 ^ 0x1B;
						}
						else
						{

							galois_multi_res[k][j] = transition_col[k][j] << 0x1;
						}
						galois_multi_res[k][j] = temp ^ galois_multi_res[k][j];
					}
					intermediate_col[i][j] ^= galois_multi_res[k][j];
				}
			}
		}
		for (n = 0; n < 4; n++)
		{
			intermediate_res[n][m] = intermediate_col[n][0];
			intermediate_col[n][0] = 0;
		}
		++m;
	}
	static state_s final_mat;
	for (i = 0; i < 4; i++)
	{

		for (j = 0; j < 4; j++)
		{
			final_mat.state[j][i] = intermediate_res[i][j] ^ key_mat->keys[j][i];
		}
	}
	return &final_mat;
}
