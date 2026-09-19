\\AES SYSTEM

`timescale 1ns / 1ps

module AES_System (
    input  wire clk,
    input  wire reset,
    input  wire start_encrypt,      
    input  wire start_decrypt,      
    input  wire [127:0] sender_key,      // NEW: Dedicated pin for the Sender's Password
    input  wire [127:0] receiver_key,    // NEW: Dedicated pin for the Receiver's Password
    
    input  wire [127:0] text_to_encrypt,   
    input  wire [127:0] cipher_to_decrypt, 

    output reg  [127:0] encrypted_output,  
    output reg  [127:0] decrypted_output,  
    output reg  encrypt_done,
    output reg  decrypt_done
);

    wire [127:0] internal_cipher_wire;
    wire internal_enc_done;
    
    wire [127:0] internal_plain_wire;
    wire internal_dec_done;

    // SENDER SIDE (Uses the Sender's Key)
    AES_Encryptor my_encrypt_block (
        .clk(clk), .reset(reset), .start(start_encrypt),
        .data_in(text_to_encrypt), .key(sender_key),
        .cipher_out(internal_cipher_wire), .done(internal_enc_done)
    );

    // RECEIVER SIDE (Uses the Receiver's Key)
    AES_Decryptor my_decrypt_block (
        .clk(clk), .reset(reset), .start(start_decrypt),
        .cipher_in(cipher_to_decrypt), .key(receiver_key),
        .plain_out(internal_plain_wire), .done(internal_dec_done)
    );

    always @(posedge clk) begin
        if (reset) begin
            encrypted_output <= 0; decrypted_output <= 0;
            encrypt_done <= 0; decrypt_done <= 0;
        end else begin
            if (internal_enc_done) begin
                encrypted_output <= internal_cipher_wire;
                encrypt_done <= 1;
            end else encrypt_done <= 0;

            if (internal_dec_done) begin
                decrypted_output <= internal_plain_wire;
                decrypt_done <= 1;
            end else decrypt_done <= 0;
        end
    end
endmodule

// ============================================================================
// THE REAL AES ENCRYPTOR (10-Round Master Controller)
// ============================================================================
module AES_Encryptor(
    input  wire clk, 
    input  wire reset, 
    input  wire start, 
    input  wire [127:0] data_in, 
    input  wire [127:0] key, 
    output reg  [127:0] cipher_out, 
    output reg  done
);

    reg [2:0] state;
    reg [3:0] round;
    reg [127:0] current_data;
    reg [127:0] current_key;

    // Wires connecting to our Math Robots
    wire [127:0] sub_out, shift_out, mix_out, next_key_out;
    
    // Instantiate the Math Robots ONCE (We reuse them every clock cycle!)
    SubBytes   robot_sub  (.state_in(current_data), .state_out(sub_out));
    ShiftRows  robot_shift(.state_in(sub_out), .state_out(shift_out));
    MixColumns robot_mix  (.state_in(shift_out), .state_out(mix_out));
    
    // Generate the "Round Constant" needed for Key Expansion
    reg [7:0] rcon;
    always @(*) begin
        case (round + 1)
            1: rcon = 8'h01; 2: rcon = 8'h02; 3: rcon = 8'h04; 4: rcon = 8'h08;
            5: rcon = 8'h10; 6: rcon = 8'h20; 7: rcon = 8'h40; 8: rcon = 8'h80;
            9: rcon = 8'h1b; 10: rcon = 8'h36; default: rcon = 8'h00;
        endcase
    end

    // Instantiate the Key Generator Robot
    NextRoundKey robot_key(.current_key(current_key), .rcon(rcon), .next_key(next_key_out));

    // The Master Controller State Machine (The Clocked Loop)
    always @(posedge clk) begin
        if (reset) begin
            state <= 0; done <= 0; cipher_out <= 0;
            current_data <= 0; current_key <= 0; round <= 0;
        end else begin
            case (state)
                0: begin // IDLE: Wait for the start signal
                    done <= 0;
                    if (start) begin
                        current_data <= data_in;
                        current_key <= key;
                        state <= 1;
                    end
                end
                
                1: begin // ROUND 0: Initial Key Addition
                    current_data <= current_data ^ current_key;
                    round <= 0;
                    state <= 2;
                end
                
                2: begin // ROUNDS 1 to 9: The Main Loop
                    current_data <= mix_out ^ next_key_out;
                    current_key <= next_key_out;
                    round <= round + 1;
                    
                    if (round == 8) state <= 3; // Once round 9 finishes, go to the final round
                end
                
                3: begin // ROUND 10: The Final Round (Notice: No MixColumns here!)
                    current_data <= shift_out ^ next_key_out; 
                    current_key <= next_key_out;
                    state <= 4;
                end
                
                4: begin // FINISHED: Lock in the cipher and trigger the done flag
                    cipher_out <= current_data;
                    done <= 1;
                    state <= 0; 
                end
            endcase
        end
    end
endmodule

// ============================================================================
// THE REAL AES DECRYPTOR (10-Round Reverse Master Controller)
// ============================================================================
module AES_Decryptor(
    input  wire clk, 
    input  wire reset, 
    input  wire start, 
    input  wire [127:0] cipher_in, 
    input  wire [127:0] key, 
    output reg  [127:0] plain_out, 
    output reg  done
);

    reg [3:0] state;
    reg [3:0] round;
    reg [127:0] current_data;
    
    // Memory bank to store all 11 Round Keys
    reg [127:0] key_mem [0:10];
    reg [127:0] current_key_gen;
    reg [3:0]   key_round;
    
    // --- THE INVERSE MATH PIPELINE ---
    // Step 1: AddRoundKey (Undo the key mixing first!)
    wire [127:0] xor_key_out = current_data ^ key_mem[round];
    
    // Step 2: InvMixColumns (Undo the Galois matrix math)
    wire [127:0] inv_mix_out;
    InvMixColumns inv_robot_mix(.state_in(xor_key_out), .state_out(inv_mix_out));
    
    // Step 3: Check if it's Round 10. (Round 10 skips InvMixColumns!)
    wire [127:0] mux_out = (round == 10) ? xor_key_out : inv_mix_out;
    
    // Step 4: InvShiftRows (Undo the wire shifting)
    wire [127:0] inv_shift_out;
    InvShiftRows inv_robot_shift(.state_in(mux_out), .state_out(inv_shift_out));
    
    // Step 5: InvSubBytes (Undo the S-Box dictionary)
    wire [127:0] inv_sub_out;
    InvSubBytes inv_robot_sub(.state_in(inv_shift_out), .state_out(inv_sub_out));
    
    // --- KEY GENERATOR (Runs first to fill the memory bank) ---
    wire [127:0] next_key_out;
    reg [7:0] rcon;
    always @(*) begin
        case (key_round + 1)
            1: rcon = 8'h01; 2: rcon = 8'h02; 3: rcon = 8'h04; 4: rcon = 8'h08;
            5: rcon = 8'h10; 6: rcon = 8'h20; 7: rcon = 8'h40; 8: rcon = 8'h80;
            9: rcon = 8'h1b; 10: rcon = 8'h36; default: rcon = 8'h00;
        endcase
    end
    NextRoundKey robot_key(.current_key(current_key_gen), .rcon(rcon), .next_key(next_key_out));

    // --- THE MASTER STATE MACHINE LOOP ---
    always @(posedge clk) begin
        if (reset) begin
            state <= 0; done <= 0; plain_out <= 0;
            current_data <= 0; round <= 10; key_round <= 0;
        end else begin
            case (state)
                0: begin // IDLE: Wait for start signal
                    done <= 0;
                    if (start) begin
                        key_mem[0] <= key;
                        current_key_gen <= key;
                        key_round <= 0;
                        state <= 1; // Go generate the keys
                    end
                end
                
                1: begin // KEY EXPANSION: Rapidly generate and save all 11 keys
                    key_mem[key_round + 1] <= next_key_out;
                    current_key_gen <= next_key_out;
                    key_round <= key_round + 1;
                    
                    if (key_round == 9) begin
                        current_data <= cipher_in;
                        round <= 10;
                        state <= 2; // Keys are saved, let's decrypt!
                    end
                end
                
                2: begin // DECRYPTION LOOP (Rounds 10 down to 1)
                    current_data <= inv_sub_out; // Push data through the inverse pipeline
                    round <= round - 1;
                    if (round == 1) state <= 3;  // When round 1 finishes, go to final XOR
                end
                
                3: begin // ROUND 0: Final Key Addition (Plaintext Recovered!)
                    plain_out <= current_data ^ key_mem[0];
                    done <= 1;
                    state <= 0;
                end
            endcase
        end
    end
endmodule