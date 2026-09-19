//twin key system 

`timescale 1ns / 1ps

// ============================================================================
// MODULE 1: THE TOP MOTHERBOARD (Full Transceiver)
// This holds BOTH the Twin-Key Sender and the Twin-Key Receiver.
// REMEMBER: Right-click this module and "Set as Top" before Synthesis!
// ============================================================================
module Twin_Key_System (
    input  wire clk,
    input  wire reset,
    input  wire start_encrypt,      
    input  wire start_decrypt,      
    
    // --- SENDER PINS ---
    input  wire [127:0] sender_key_1,
    input  wire [127:0] sender_key_2,
    input  wire [127:0] text_to_encrypt,   
    output reg  [127:0] encrypted_output,  
    output reg  encrypt_done,

    // --- RECEIVER PINS ---
    input  wire [127:0] receiver_key_1,
    input  wire [127:0] receiver_key_2,
    input  wire [127:0] cipher_to_decrypt, 
    output reg  [127:0] decrypted_output,  
    output reg  decrypt_done
);

    // ---------------------------------------------------------
    // 1. SENDER SIDE (The Hardware-Shared Twin Encryptor)
    // ---------------------------------------------------------
    wire [127:0] internal_cipher_wire;
    wire internal_enc_done;
    
    Twin_Key_AES my_twin_encryptor (
        .clk(clk),
        .reset(reset),
        .start_process(start_encrypt),
        .plaintext_in(text_to_encrypt),
        .key_1(sender_key_1),
        .key_2(sender_key_2),
        .final_ciphertext_out(internal_cipher_wire),
        .process_done(internal_enc_done)
    );

    // ---------------------------------------------------------
    // 2. RECEIVER SIDE (The Hardware-Shared Twin Decryptor)
    // ---------------------------------------------------------
    wire [127:0] final_plain_wire;
    wire internal_dec_done;

    Twin_Key_Decryptor my_twin_decryptor (
        .clk(clk),
        .reset(reset),
        .start_process(start_decrypt),
        .ciphertext_in(cipher_to_decrypt),
        .receiver_key_1(receiver_key_1),
        .receiver_key_2(receiver_key_2),
        .final_plaintext_out(final_plain_wire),
        .process_done(internal_dec_done)
    );

    // ---------------------------------------------------------
    // 3. OUTPUT REGISTERS (Clocked synchronization)
    // ---------------------------------------------------------
    always @(posedge clk) begin
        if (reset) begin
            encrypted_output <= 0; 
            decrypted_output <= 0;
            encrypt_done <= 0; 
            decrypt_done <= 0;
        end else begin
            // Encryptor Output Catch
            if (internal_enc_done) begin
                encrypted_output <= internal_cipher_wire;
                encrypt_done <= 1;
            end else encrypt_done <= 0;

            // Decryptor Output Catch
            if (internal_dec_done) begin
                decrypted_output <= final_plain_wire;
                decrypt_done <= 1;
            end else decrypt_done <= 0;
        end
    end
endmodule


// ============================================================================
// MODULE 2: THE SENDER SMART BOSS (Hardware Sharing for Encryption)
// ============================================================================
module Twin_Key_AES (
    input wire clk,
    input wire reset,
    input wire start_process,
    input wire [127:0] plaintext_in,
    input wire [127:0] key_1,
    input wire [127:0] key_2,
    output reg [127:0] final_ciphertext_out,
    output reg process_done
);

    parameter IDLE         = 3'd0;
    parameter ENC_STAGE_1  = 3'd1;
    parameter WAIT_STAGE_1 = 3'd2;
    parameter ENC_STAGE_2  = 3'd3;
    parameter WAIT_STAGE_2 = 3'd4;
    parameter DONE         = 3'd5;

    reg [2:0] state;
    
    reg single_start;
    reg [127:0] single_data_in;
    reg [127:0] single_key_in;
    wire [127:0] single_cipher_out;
    wire single_done;

    // --- Instantiate the ONE Math Engine ---
    AES_Encryptor Shared_Engine (
        .clk(clk),
        .reset(reset),
        .start(single_start),
        .data_in(single_data_in),
        .key(single_key_in),
        .cipher_out(single_cipher_out),
        .done(single_done)
    );

    always @(posedge clk) begin
        if (reset) begin
            state <= IDLE;
            final_ciphertext_out <= 128'd0;
            process_done <= 0;
            single_start <= 0;
        end else begin
            case (state)
                IDLE: begin
                    process_done <= 0;
                    if (start_process) begin
                        single_data_in <= plaintext_in;
                        single_key_in <= key_1; // Lock 1
                        single_start <= 1;
                        state <= ENC_STAGE_1;
                    end
                end

                ENC_STAGE_1: begin
                    single_start <= 0; 
                    state <= WAIT_STAGE_1;
                end

                WAIT_STAGE_1: begin
                    if (single_done) begin
                        single_data_in <= single_cipher_out;
                        single_key_in <= key_2; // Lock 2
                        single_start <= 1;
                        state <= ENC_STAGE_2;
                    end
                end

                ENC_STAGE_2: begin
                    single_start <= 0; 
                    state <= WAIT_STAGE_2;
                end

                WAIT_STAGE_2: begin
                    if (single_done) begin
                        final_ciphertext_out <= single_cipher_out;
                        process_done <= 1;
                        state <= DONE;
                    end
                end

                DONE: begin
                    state <= IDLE; 
                end
            endcase
        end
    end
endmodule


// ============================================================================
// MODULE 3: THE RECEIVER SMART BOSS (Hardware Sharing for Decryption)
// ============================================================================
module Twin_Key_Decryptor (
    input wire clk,
    input wire reset,
    input wire start_process,
    input wire [127:0] ciphertext_in,
    input wire [127:0] receiver_key_1,
    input wire [127:0] receiver_key_2,
    output reg [127:0] final_plaintext_out,
    output reg process_done
);

    parameter IDLE         = 3'd0;
    parameter DEC_STAGE_1  = 3'd1;
    parameter WAIT_STAGE_1 = 3'd2;
    parameter DEC_STAGE_2  = 3'd3;
    parameter WAIT_STAGE_2 = 3'd4;
    parameter DONE         = 3'd5;

    reg [2:0] state;
    
    reg single_start;
    reg [127:0] single_cipher_in;
    reg [127:0] single_key_in;
    wire [127:0] single_plain_out;
    wire single_done;

    // --- Instantiate the ONE Math Engine ---
    AES_Decryptor Shared_Dec_Engine (
        .clk(clk),
        .reset(reset),
        .start(single_start),
        .cipher_in(single_cipher_in),
        .key(single_key_in),
        .plain_out(single_plain_out),
        .done(single_done)
    );

    always @(posedge clk) begin
        if (reset) begin
            state <= IDLE;
            final_plaintext_out <= 128'd0;
            process_done <= 0;
            single_start <= 0;
        end else begin
            case (state)
                IDLE: begin
                    process_done <= 0;
                    if (start_process) begin
                        single_cipher_in <= ciphertext_in;
                        single_key_in <= receiver_key_2; // Unlock 2 FIRST!
                        single_start <= 1;
                        state <= DEC_STAGE_1;
                    end
                end

                DEC_STAGE_1: begin
                    single_start <= 0; 
                    state <= WAIT_STAGE_1;
                end

                WAIT_STAGE_1: begin
                    if (single_done) begin
                        single_cipher_in <= single_plain_out;
                        single_key_in <= receiver_key_1; // Then Unlock 1!
                        single_start <= 1;
                        state <= DEC_STAGE_2;
                    end
                end

                DEC_STAGE_2: begin
                    single_start <= 0; 
                    state <= WAIT_STAGE_2;
                end

                WAIT_STAGE_2: begin
                    if (single_done) begin
                        final_plaintext_out <= single_plain_out;
                        process_done <= 1;
                        state <= DONE;
                    end
                end

                DONE: begin
                    state <= IDLE; 
                end
            endcase
        end
    end
endmodule


//aes system

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

//aes math block

`timescale 1ns / 1ps

// ============================================================================
// ROBOT 1: AddRoundKey
// WHY: This is the easiest step. In hardware, combining data with a key 
// is done using 128 physical XOR logic gates in parallel.
// ============================================================================
module AddRoundKey (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);
    assign state_out = state_in ^ round_key;
endmodule

// ============================================================================
// ROBOT 2: ShiftRows
// WHY: There is no math here, just physical rewiring! We chop the 128 wires 
// into 16 chunks (bytes) and physically solder them to different output pins 
// to scramble the order diagonally.
// ============================================================================
module ShiftRows (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    assign state_out = {
        state_in[127:120], state_in[87:80],   state_in[47:40],   state_in[7:0],     // Row 0: No shift
        state_in[95:88],   state_in[55:48],   state_in[15:8],    state_in[103:96],  // Row 1: Shift Left 1
        state_in[63:56],   state_in[23:16],   state_in[111:104], state_in[71:64],   // Row 2: Shift Left 2
        state_in[31:24],   state_in[119:112], state_in[79:72],   state_in[39:32]    // Row 3: Shift Left 3
    };
endmodule

// ============================================================================
// ROBOT 3: SubBytes (The S-Box)
// WHY: This is a massive Look-Up Table (LUT). Instead of doing complex 
// division, the FPGA just looks at the 8-bit input, checks the dictionary, 
// and instantly fires out the substituted 8-bit output.
// ============================================================================
module SubBytes (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    // We instantiate 16 Look-Up Tables to process all 16 bytes simultaneously
    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : sbox_loop
            SBox my_sbox (
                .in_byte (state_in[(i*8)+7 : i*8]),
                .out_byte(state_out[(i*8)+7 : i*8])
            );
        end
    endgenerate
endmodule

// The actual physical dictionary (S-Box)
module SBox (
    input  wire [7:0] in_byte,
    output reg  [7:0] out_byte
);
    always @(*) begin
        case (in_byte)
            8'h00: out_byte = 8'h63; 8'h01: out_byte = 8'h7c; 8'h02: out_byte = 8'h77; 8'h03: out_byte = 8'h7b;
            8'h04: out_byte = 8'hf2; 8'h05: out_byte = 8'h6b; 8'h06: out_byte = 8'h6f; 8'h07: out_byte = 8'hc5;
            8'h08: out_byte = 8'h30; 8'h09: out_byte = 8'h01; 8'h0a: out_byte = 8'h67; 8'h0b: out_byte = 8'h2b;
            8'h0c: out_byte = 8'hfe; 8'h0d: out_byte = 8'hd7; 8'h0e: out_byte = 8'hab; 8'h0f: out_byte = 8'h76;
            8'h10: out_byte = 8'hca; 8'h11: out_byte = 8'h82; 8'h12: out_byte = 8'hc9; 8'h13: out_byte = 8'h7d;
            8'h14: out_byte = 8'hfa; 8'h15: out_byte = 8'h59; 8'h16: out_byte = 8'h47; 8'h17: out_byte = 8'hf0;
            8'h18: out_byte = 8'had; 8'h19: out_byte = 8'hd4; 8'h1a: out_byte = 8'ha2; 8'h1b: out_byte = 8'haf;
            8'h1c: out_byte = 8'h9c; 8'h1d: out_byte = 8'ha4; 8'h1e: out_byte = 8'h72; 8'h1f: out_byte = 8'hc0;
            8'h20: out_byte = 8'hb7; 8'h21: out_byte = 8'hfd; 8'h22: out_byte = 8'h93; 8'h23: out_byte = 8'h26;
            8'h24: out_byte = 8'h36; 8'h25: out_byte = 8'h3f; 8'h26: out_byte = 8'hf7; 8'h27: out_byte = 8'hcc;
            8'h28: out_byte = 8'h34; 8'h29: out_byte = 8'ha5; 8'h2a: out_byte = 8'he5; 8'h2b: out_byte = 8'hf1;
            8'h2c: out_byte = 8'h71; 8'h2d: out_byte = 8'hd8; 8'h2e: out_byte = 8'h31; 8'h2f: out_byte = 8'h15;
            8'h30: out_byte = 8'h04; 8'h31: out_byte = 8'hc7; 8'h32: out_byte = 8'h23; 8'h33: out_byte = 8'hc3;
            8'h34: out_byte = 8'h18; 8'h35: out_byte = 8'h96; 8'h36: out_byte = 8'h05; 8'h37: out_byte = 8'h9a;
            8'h38: out_byte = 8'h07; 8'h39: out_byte = 8'h12; 8'h3a: out_byte = 8'h80; 8'h3b: out_byte = 8'he2;
            8'h3c: out_byte = 8'heb; 8'h3d: out_byte = 8'h27; 8'h3e: out_byte = 8'hb2; 8'h3f: out_byte = 8'h75;
            8'h40: out_byte = 8'h09; 8'h41: out_byte = 8'h83; 8'h42: out_byte = 8'h2c; 8'h43: out_byte = 8'h1a;
            8'h44: out_byte = 8'h1b; 8'h45: out_byte = 8'h6e; 8'h46: out_byte = 8'h5a; 8'h47: out_byte = 8'ha0;
            8'h48: out_byte = 8'h52; 8'h49: out_byte = 8'h3b; 8'h4a: out_byte = 8'hd6; 8'h4b: out_byte = 8'hb3;
            8'h4c: out_byte = 8'h29; 8'h4d: out_byte = 8'he3; 8'h4e: out_byte = 8'h2f; 8'h4f: out_byte = 8'h84;
            8'h50: out_byte = 8'h53; 8'h51: out_byte = 8'hd1; 8'h52: out_byte = 8'h00; 8'h53: out_byte = 8'hed;
            8'h54: out_byte = 8'h20; 8'h55: out_byte = 8'hfc; 8'h56: out_byte = 8'hb1; 8'h57: out_byte = 8'h5b;
            8'h58: out_byte = 8'h6a; 8'h59: out_byte = 8'hcb; 8'h5a: out_byte = 8'hbe; 8'h5b: out_byte = 8'h39;
            8'h5c: out_byte = 8'h4a; 8'h5d: out_byte = 8'h4c; 8'h5e: out_byte = 8'h58; 8'h5f: out_byte = 8'hcf;
            8'h60: out_byte = 8'hd0; 8'h61: out_byte = 8'hef; 8'h62: out_byte = 8'haa; 8'h63: out_byte = 8'hfb;
            8'h64: out_byte = 8'h43; 8'h65: out_byte = 8'h4d; 8'h66: out_byte = 8'h33; 8'h67: out_byte = 8'h85;
            8'h68: out_byte = 8'h45; 8'h69: out_byte = 8'hf9; 8'h6a: out_byte = 8'h02; 8'h6b: out_byte = 8'h7f;
            8'h6c: out_byte = 8'h50; 8'h6d: out_byte = 8'h3c; 8'h6e: out_byte = 8'h9f; 8'h6f: out_byte = 8'ha8;
            8'h70: out_byte = 8'h51; 8'h71: out_byte = 8'ha3; 8'h72: out_byte = 8'h40; 8'h73: out_byte = 8'h8f;
            8'h74: out_byte = 8'h92; 8'h75: out_byte = 8'h9d; 8'h76: out_byte = 8'h38; 8'h77: out_byte = 8'hf5;
            8'h78: out_byte = 8'hbc; 8'h79: out_byte = 8'hb6; 8'h7a: out_byte = 8'hda; 8'h7b: out_byte = 8'h21;
            8'h7c: out_byte = 8'h10; 8'h7d: out_byte = 8'hff; 8'h7e: out_byte = 8'hf3; 8'h7f: out_byte = 8'hd2;
            8'h80: out_byte = 8'hcd; 8'h81: out_byte = 8'h0c; 8'h82: out_byte = 8'h13; 8'h83: out_byte = 8'hec;
            8'h84: out_byte = 8'h5f; 8'h85: out_byte = 8'h97; 8'h86: out_byte = 8'h44; 8'h87: out_byte = 8'h17;
            8'h88: out_byte = 8'hc4; 8'h89: out_byte = 8'ha7; 8'h8a: out_byte = 8'h7e; 8'h8b: out_byte = 8'h3d;
            8'h8c: out_byte = 8'h64; 8'h8d: out_byte = 8'h5d; 8'h8e: out_byte = 8'h19; 8'h8f: out_byte = 8'h73;
            8'h90: out_byte = 8'h60; 8'h91: out_byte = 8'h81; 8'h92: out_byte = 8'h4f; 8'h93: out_byte = 8'hdc;
            8'h94: out_byte = 8'h22; 8'h95: out_byte = 8'h2a; 8'h96: out_byte = 8'h90; 8'h97: out_byte = 8'h88;
            8'h98: out_byte = 8'h46; 8'h99: out_byte = 8'hee; 8'h9a: out_byte = 8'hb8; 8'h9b: out_byte = 8'h14;
            8'h9c: out_byte = 8'hde; 8'h9d: out_byte = 8'h5e; 8'h9e: out_byte = 8'h0b; 8'h9f: out_byte = 8'hdb;
            8'ha0: out_byte = 8'he0; 8'ha1: out_byte = 8'h32; 8'ha2: out_byte = 8'h3a; 8'ha3: out_byte = 8'h0a;
            8'ha4: out_byte = 8'h49; 8'ha5: out_byte = 8'h06; 8'ha6: out_byte = 8'h24; 8'ha7: out_byte = 8'h5c;
            8'ha8: out_byte = 8'hc2; 8'ha9: out_byte = 8'hd3; 8'haa: out_byte = 8'hac; 8'hab: out_byte = 8'h62;
            8'hac: out_byte = 8'h91; 8'had: out_byte = 8'h95; 8'hae: out_byte = 8'he4; 8'haf: out_byte = 8'h79;
            8'hb0: out_byte = 8'he7; 8'hb1: out_byte = 8'hc8; 8'hb2: out_byte = 8'h37; 8'hb3: out_byte = 8'h6d;
            8'hb4: out_byte = 8'h8d; 8'hb5: out_byte = 8'hd5; 8'hb6: out_byte = 8'h4e; 8'hb7: out_byte = 8'ha9;
            8'hb8: out_byte = 8'h6c; 8'hb9: out_byte = 8'h56; 8'hba: out_byte = 8'hf4; 8'hbb: out_byte = 8'hea;
            8'hbc: out_byte = 8'h65; 8'hbd: out_byte = 8'h7a; 8'hbe: out_byte = 8'hae; 8'hbf: out_byte = 8'h08;
            8'hc0: out_byte = 8'hba; 8'hc1: out_byte = 8'h78; 8'hc2: out_byte = 8'h25; 8'hc3: out_byte = 8'h2e;
            8'hc4: out_byte = 8'h1c; 8'hc5: out_byte = 8'ha6; 8'hc6: out_byte = 8'hb4; 8'hc7: out_byte = 8'hc6;
            8'hc8: out_byte = 8'he8; 8'hc9: out_byte = 8'hdd; 8'hca: out_byte = 8'h74; 8'hcb: out_byte = 8'h1f;
            8'hcc: out_byte = 8'h4b; 8'hcd: out_byte = 8'hbd; 8'hce: out_byte = 8'h8b; 8'hcf: out_byte = 8'h8a;
            8'hd0: out_byte = 8'h70; 8'hd1: out_byte = 8'h3e; 8'hd2: out_byte = 8'hb5; 8'hd3: out_byte = 8'h66;
            8'hd4: out_byte = 8'h48; 8'hd5: out_byte = 8'h03; 8'hd6: out_byte = 8'hf6; 8'hd7: out_byte = 8'h0e;
            8'hd8: out_byte = 8'h61; 8'hd9: out_byte = 8'h35; 8'hda: out_byte = 8'h57; 8'hdb: out_byte = 8'hb9;
            8'hdc: out_byte = 8'h86; 8'hdd: out_byte = 8'hc1; 8'hde: out_byte = 8'h1d; 8'hdf: out_byte = 8'h9e;
            8'he0: out_byte = 8'he1; 8'he1: out_byte = 8'hf8; 8'he2: out_byte = 8'h98; 8'he3: out_byte = 8'h11;
            8'he4: out_byte = 8'h69; 8'he5: out_byte = 8'hd9; 8'he6: out_byte = 8'h8e; 8'he7: out_byte = 8'h94;
            8'he8: out_byte = 8'h9b; 8'he9: out_byte = 8'h1e; 8'hea: out_byte = 8'h87; 8'heb: out_byte = 8'he9;
            8'hec: out_byte = 8'hce; 8'hed: out_byte = 8'h55; 8'hee: out_byte = 8'h28; 8'hef: out_byte = 8'hdf;
            8'hf0: out_byte = 8'h8c; 8'hf1: out_byte = 8'ha1; 8'hf2: out_byte = 8'h89; 8'hf3: out_byte = 8'h0d;
            8'hf4: out_byte = 8'hbf; 8'hf5: out_byte = 8'he6; 8'hf6: out_byte = 8'h42; 8'hf7: out_byte = 8'h68;
            8'hf8: out_byte = 8'h41; 8'hf9: out_byte = 8'h99; 8'hfa: out_byte = 8'h2d; 8'hfb: out_byte = 8'h0f;
            8'hfc: out_byte = 8'hb0; 8'hfd: out_byte = 8'h54; 8'hfe: out_byte = 8'hbb; 8'hff: out_byte = 8'h16;
            default: out_byte = 8'h00;
        endcase
    end
endmodule

// ============================================================================
// ROBOT 4: MixColumns (Galois Field Multiplier)
// WHY: Multiplication in standard math takes too much hardware power. 
// Instead, we use "Galois Field" multiplication, which uses a clever bit-shift 
// and an XOR logic trick to instantly calculate the matrix algebra.
// ============================================================================
module MixColumns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    // Process the 4 columns simultaneously
    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : mix_loop
            MixSingleColumn my_mixer (
                .col_in (state_in[(i*32)+31 : i*32]),
                .col_out(state_out[(i*32)+31 : i*32])
            );
        end
    endgenerate
endmodule

// The actual Galois Field Math for a single column
module MixSingleColumn (
    input  wire [31:0] col_in,
    output wire [31:0] col_out
);
    wire [7:0] s0, s1, s2, s3;
    assign {s3, s2, s1, s0} = col_in;

    // The special Galois Field Multiply-by-2 Function
    function [7:0] gf_mul2;
        input [7:0] x;
        // If the left-most bit is 1, shift left and XOR with 0x1B (AES standard polynomial)
        gf_mul2 = (x[7] == 1) ? ((x << 1) ^ 8'h1b) : (x << 1);
    endfunction

    // Matrix Multiplication logic using the function
    assign col_out[31:24] = gf_mul2(s3) ^ gf_mul2(s2) ^ s2 ^ s1 ^ s0;
    assign col_out[23:16] = s3 ^ gf_mul2(s2) ^ gf_mul2(s1) ^ s1 ^ s0;
    assign col_out[15:8]  = s3 ^ s2 ^ gf_mul2(s1) ^ gf_mul2(s0) ^ s0;
    assign col_out[7:0]   = gf_mul2(s3) ^ s3 ^ s2 ^ s1 ^ gf_mul2(s0);

endmodule
// ============================================================================
// ROBOT 5: Key Expansion (Next Round Key Generator)
// WHY: This takes the 128-bit password from the previous round and generates 
// a brand new 128-bit password for the current round. It uses the S-Box 
// and a "Round Constant" (Rcon) to prevent hackers from finding a pattern.
// ============================================================================
module NextRoundKey (
    input  wire [127:0] current_key,  // The password from the previous round
    input  wire [7:0]   rcon,         // A special constant number for the current round
    output wire [127:0] next_key      // The newly generated password
);
    // 1. Split the 128-bit key into four 32-bit words
    wire [31:0] w0, w1, w2, w3;
    wire [31:0] next_w0, next_w1, next_w2, next_w3;
    
    assign {w0, w1, w2, w3} = current_key;

    // 2. RotWord: Take the last word (w3) and shift it left by 1 byte
    wire [31:0] rot_word;
    assign rot_word = {w3[23:0], w3[31:24]};

    // 3. SubWord: Pass that rotated word through the S-Box dictionary
    wire [31:0] sub_word;
    SBox sb0(.in_byte(rot_word[31:24]), .out_byte(sub_word[31:24]));
    SBox sb1(.in_byte(rot_word[23:16]), .out_byte(sub_word[23:16]));
    SBox sb2(.in_byte(rot_word[15:8]),  .out_byte(sub_word[15:8]));
    SBox sb3(.in_byte(rot_word[7:0]),   .out_byte(sub_word[7:0]));

    // 4. XOR all the parts together with the Round Constant to create the new words
    assign next_w0 = w0 ^ sub_word ^ {rcon, 24'h000000};
    assign next_w1 = w1 ^ next_w0;
    assign next_w2 = w2 ^ next_w1;
    assign next_w3 = w3 ^ next_w2;

    // 5. Bundle the 4 new words together into the new 128-bit Round Key!
    assign next_key = {next_w0, next_w1, next_w2, next_w3};

endmodule
// ============================================================================
// INVERSE ROBOT 1: InvShiftRows
// WHY: We physically rewire the bytes to shift to the RIGHT instead of the left,
// putting them back in their exact original columns.
// ============================================================================
module InvShiftRows (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    assign state_out = {
        state_in[127:120], state_in[23:16],   state_in[47:40],   state_in[71:64],
        state_in[95:88],   state_in[119:112], state_in[15:8],    state_in[39:32],
        state_in[63:56],   state_in[87:80],   state_in[111:104], state_in[7:0],
        state_in[31:24],   state_in[55:48],   state_in[79:72],   state_in[103:96]
    };
endmodule

// ============================================================================
// INVERSE ROBOT 2: InvSubBytes (The Reverse Dictionary)
// WHY: This is the exact opposite of the original Look-Up Table. 
// ============================================================================
module InvSubBytes (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : inv_sbox_loop
            InvSBox my_inv_sbox (
                .in_byte (state_in[(i*8)+7 : i*8]),
                .out_byte(state_out[(i*8)+7 : i*8])
            );
        end
    endgenerate
endmodule

module InvSBox (
    input  wire [7:0] in_byte,
    output reg  [7:0] out_byte
);
    always @(*) begin
        case (in_byte)
            8'h00: out_byte = 8'h52; 8'h01: out_byte = 8'h09; 8'h02: out_byte = 8'h6a; 8'h03: out_byte = 8'hd5;
            8'h04: out_byte = 8'h30; 8'h05: out_byte = 8'h36; 8'h06: out_byte = 8'ha5; 8'h07: out_byte = 8'h38;
            8'h08: out_byte = 8'hbf; 8'h09: out_byte = 8'h40; 8'h0a: out_byte = 8'ha3; 8'h0b: out_byte = 8'h9e;
            8'h0c: out_byte = 8'h81; 8'h0d: out_byte = 8'hf3; 8'h0e: out_byte = 8'hd7; 8'h0f: out_byte = 8'hfb;
            8'h10: out_byte = 8'h7c; 8'h11: out_byte = 8'he3; 8'h12: out_byte = 8'h39; 8'h13: out_byte = 8'h82;
            8'h14: out_byte = 8'h9b; 8'h15: out_byte = 8'h2f; 8'h16: out_byte = 8'hff; 8'h17: out_byte = 8'h87;
            8'h18: out_byte = 8'h34; 8'h19: out_byte = 8'h8e; 8'h1a: out_byte = 8'h43; 8'h1b: out_byte = 8'h44;
            8'h1c: out_byte = 8'hc4; 8'h1d: out_byte = 8'hde; 8'h1e: out_byte = 8'he9; 8'h1f: out_byte = 8'hcb;
            8'h20: out_byte = 8'h54; 8'h21: out_byte = 8'h7b; 8'h22: out_byte = 8'h94; 8'h23: out_byte = 8'h32;
            8'h24: out_byte = 8'ha6; 8'h25: out_byte = 8'hc2; 8'h26: out_byte = 8'h23; 8'h27: out_byte = 8'h3d;
            8'h28: out_byte = 8'hee; 8'h29: out_byte = 8'h4c; 8'h2a: out_byte = 8'h95; 8'h2b: out_byte = 8'h0b;
            8'h2c: out_byte = 8'h42; 8'h2d: out_byte = 8'hfa; 8'h2e: out_byte = 8'hc3; 8'h2f: out_byte = 8'h4e;
            8'h30: out_byte = 8'h08; 8'h31: out_byte = 8'h2e; 8'h32: out_byte = 8'ha1; 8'h33: out_byte = 8'h66;
            8'h34: out_byte = 8'h28; 8'h35: out_byte = 8'hd9; 8'h36: out_byte = 8'h24; 8'h37: out_byte = 8'hb2;
            8'h38: out_byte = 8'h76; 8'h39: out_byte = 8'h5b; 8'h3a: out_byte = 8'ha2; 8'h3b: out_byte = 8'h49;
            8'h3c: out_byte = 8'h6d; 8'h3d: out_byte = 8'h8b; 8'h3e: out_byte = 8'hd1; 8'h3f: out_byte = 8'h25;
            8'h40: out_byte = 8'h72; 8'h41: out_byte = 8'hf8; 8'h42: out_byte = 8'hf6; 8'h43: out_byte = 8'h64;
            8'h44: out_byte = 8'h86; 8'h45: out_byte = 8'h68; 8'h46: out_byte = 8'h98; 8'h47: out_byte = 8'h16;
            8'h48: out_byte = 8'hd4; 8'h49: out_byte = 8'ha4; 8'h4a: out_byte = 8'h5c; 8'h4b: out_byte = 8'hcc;
            8'h4c: out_byte = 8'h5d; 8'h4d: out_byte = 8'h65; 8'h4e: out_byte = 8'hb6; 8'h4f: out_byte = 8'h92;
            8'h50: out_byte = 8'h6c; 8'h51: out_byte = 8'h70; 8'h52: out_byte = 8'h48; 8'h53: out_byte = 8'h50;
            8'h54: out_byte = 8'hfd; 8'h55: out_byte = 8'hed; 8'h56: out_byte = 8'hb9; 8'h57: out_byte = 8'hda;
            8'h58: out_byte = 8'h5e; 8'h59: out_byte = 8'h15; 8'h5a: out_byte = 8'h46; 8'h5b: out_byte = 8'h57;
            8'h5c: out_byte = 8'ha7; 8'h5d: out_byte = 8'h8d; 8'h5e: out_byte = 8'h9d; 8'h5f: out_byte = 8'h84;
            8'h60: out_byte = 8'h90; 8'h61: out_byte = 8'hd8; 8'h62: out_byte = 8'hab; 8'h63: out_byte = 8'h00;
            8'h64: out_byte = 8'h8c; 8'h65: out_byte = 8'hbc; 8'h66: out_byte = 8'hd3; 8'h67: out_byte = 8'h0a;
            8'h68: out_byte = 8'hf7; 8'h69: out_byte = 8'he4; 8'h6a: out_byte = 8'h58; 8'h6b: out_byte = 8'h05;
            8'h6c: out_byte = 8'hb8; 8'h6d: out_byte = 8'hb3; 8'h6e: out_byte = 8'h45; 8'h6f: out_byte = 8'h06;
            8'h70: out_byte = 8'hd0; 8'h71: out_byte = 8'h2c; 8'h72: out_byte = 8'h1e; 8'h73: out_byte = 8'h8f;
            8'h74: out_byte = 8'hca; 8'h75: out_byte = 8'h3f; 8'h76: out_byte = 8'h0f; 8'h77: out_byte = 8'h02;
            8'h78: out_byte = 8'hc1; 8'h79: out_byte = 8'haf; 8'h7a: out_byte = 8'hbd; 8'h7b: out_byte = 8'h03;
            8'h7c: out_byte = 8'h01; 8'h7d: out_byte = 8'h13; 8'h7e: out_byte = 8'h8a; 8'h7f: out_byte = 8'h6b;
            8'h80: out_byte = 8'h3a; 8'h81: out_byte = 8'h91; 8'h82: out_byte = 8'h11; 8'h83: out_byte = 8'h41;
            8'h84: out_byte = 8'h4f; 8'h85: out_byte = 8'h67; 8'h86: out_byte = 8'hdc; 8'h87: out_byte = 8'hea;
            8'h88: out_byte = 8'h97; 8'h89: out_byte = 8'hf2; 8'h8a: out_byte = 8'hcf; 8'h8b: out_byte = 8'hce;
            8'h8c: out_byte = 8'hf0; 8'h8d: out_byte = 8'hb4; 8'h8e: out_byte = 8'he6; 8'h8f: out_byte = 8'h73;
            8'h90: out_byte = 8'h96; 8'h91: out_byte = 8'hac; 8'h92: out_byte = 8'h74; 8'h93: out_byte = 8'h22;
            8'h94: out_byte = 8'he7; 8'h95: out_byte = 8'had; 8'h96: out_byte = 8'h35; 8'h97: out_byte = 8'h85;
            8'h98: out_byte = 8'he2; 8'h99: out_byte = 8'hf9; 8'h9a: out_byte = 8'h37; 8'h9b: out_byte = 8'he8;
            8'h9c: out_byte = 8'h1c; 8'h9d: out_byte = 8'h75; 8'h9e: out_byte = 8'hdf; 8'h9f: out_byte = 8'h6e;
            8'ha0: out_byte = 8'h47; 8'ha1: out_byte = 8'hf1; 8'ha2: out_byte = 8'h1a; 8'ha3: out_byte = 8'h71;
            8'ha4: out_byte = 8'h1d; 8'ha5: out_byte = 8'h29; 8'ha6: out_byte = 8'hc5; 8'ha7: out_byte = 8'h89;
            8'ha8: out_byte = 8'h6f; 8'ha9: out_byte = 8'hb7; 8'haa: out_byte = 8'h62; 8'hab: out_byte = 8'h0e;
            8'hac: out_byte = 8'haa; 8'had: out_byte = 8'h18; 8'hae: out_byte = 8'hbe; 8'haf: out_byte = 8'h1b;
            8'hb0: out_byte = 8'hfc; 8'hb1: out_byte = 8'h56; 8'hb2: out_byte = 8'h3e; 8'hb3: out_byte = 8'h4b;
            8'hb4: out_byte = 8'hc6; 8'hb5: out_byte = 8'hd2; 8'hb6: out_byte = 8'h79; 8'hb7: out_byte = 8'h20;
            8'hb8: out_byte = 8'h9a; 8'hb9: out_byte = 8'hdb; 8'hba: out_byte = 8'hc0; 8'hbb: out_byte = 8'hfe;
            8'hbc: out_byte = 8'h78; 8'hbd: out_byte = 8'hcd; 8'hbe: out_byte = 8'h5a; 8'hbf: out_byte = 8'hf4;
            8'hc0: out_byte = 8'h1f; 8'hc1: out_byte = 8'hdd; 8'hc2: out_byte = 8'ha8; 8'hc3: out_byte = 8'h33;
            8'hc4: out_byte = 8'h88; 8'hc5: out_byte = 8'h07; 8'hc6: out_byte = 8'hc7; 8'hc7: out_byte = 8'h31;
            8'hc8: out_byte = 8'hb1; 8'hc9: out_byte = 8'h12; 8'hca: out_byte = 8'h10; 8'hcb: out_byte = 8'h59;
            8'hcc: out_byte = 8'h27; 8'hcd: out_byte = 8'h80; 8'hce: out_byte = 8'hec; 8'hcf: out_byte = 8'h5f;
            8'hd0: out_byte = 8'h60; 8'hd1: out_byte = 8'h51; 8'hd2: out_byte = 8'h7f; 8'hd3: out_byte = 8'ha9;
            8'hd4: out_byte = 8'h19; 8'hd5: out_byte = 8'hb5; 8'hd6: out_byte = 8'h4a; 8'hd7: out_byte = 8'h0d;
            8'hd8: out_byte = 8'h2d; 8'hd9: out_byte = 8'he5; 8'hda: out_byte = 8'h7a; 8'hdb: out_byte = 8'h9f;
            8'hdc: out_byte = 8'h93; 8'hdd: out_byte = 8'hc9; 8'hde: out_byte = 8'h9c; 8'hdf: out_byte = 8'hef;
            8'he0: out_byte = 8'ha0; 8'he1: out_byte = 8'he0; 8'he2: out_byte = 8'h3b; 8'he3: out_byte = 8'h4d;
            8'he4: out_byte = 8'hae; 8'he5: out_byte = 8'h2a; 8'he6: out_byte = 8'hf5; 8'he7: out_byte = 8'hb0;
            8'he8: out_byte = 8'hc8; 8'he9: out_byte = 8'heb; 8'hea: out_byte = 8'hbb; 8'heb: out_byte = 8'h3c;
            8'hec: out_byte = 8'h83; 8'hed: out_byte = 8'h53; 8'hee: out_byte = 8'h99; 8'hef: out_byte = 8'h61;
            8'hf0: out_byte = 8'h17; 8'hf1: out_byte = 8'h2b; 8'hf2: out_byte = 8'h04; 8'hf3: out_byte = 8'h7e;
            8'hf4: out_byte = 8'hba; 8'hf5: out_byte = 8'h77; 8'hf6: out_byte = 8'hd6; 8'hf7: out_byte = 8'h26;
            8'hf8: out_byte = 8'he1; 8'hf9: out_byte = 8'h69; 8'hfa: out_byte = 8'h14; 8'hfb: out_byte = 8'h63;
            8'hfc: out_byte = 8'h55; 8'hfd: out_byte = 8'h21; 8'hfe: out_byte = 8'h0c; 8'hff: out_byte = 8'h7d;
            default: out_byte = 8'h00;
        endcase
    end
endmodule

// ============================================================================
// INVERSE ROBOT 3: InvMixColumns
// WHY: We have to multiply the matrix by much harder Galois Field numbers 
// (9, 11, 13, and 14) to unravel the forward matrix math!
// ============================================================================
module InvMixColumns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : inv_mix_loop
            InvMixSingleColumn my_inv_mixer (
                .col_in (state_in[(i*32)+31 : i*32]),
                .col_out(state_out[(i*32)+31 : i*32])
            );
        end
    endgenerate
endmodule

module InvMixSingleColumn (
    input  wire [31:0] col_in,
    output wire [31:0] col_out
);
    wire [7:0] s0, s1, s2, s3;
    assign {s3, s2, s1, s0} = col_in;

    // Advanced Galois Field Multipliers built out of our original Multiply-by-2 block
    function [7:0] gf_mul2; input [7:0] x; gf_mul2 = (x[7]) ? ((x << 1) ^ 8'h1b) : (x << 1); endfunction
    function [7:0] gf_mul4; input [7:0] x; gf_mul4 = gf_mul2(gf_mul2(x)); endfunction
    function [7:0] gf_mul8; input [7:0] x; gf_mul8 = gf_mul2(gf_mul4(x)); endfunction
    
    function [7:0] gf_mul9; input [7:0] x; gf_mul9 = gf_mul8(x) ^ x; endfunction
    function [7:0] gf_mul_b; input [7:0] x; gf_mul_b = gf_mul8(x) ^ gf_mul2(x) ^ x; endfunction
    function [7:0] gf_mul_d; input [7:0] x; gf_mul_d = gf_mul8(x) ^ gf_mul4(x) ^ x; endfunction
    function [7:0] gf_mul_e; input [7:0] x; gf_mul_e = gf_mul8(x) ^ gf_mul4(x) ^ gf_mul2(x); endfunction

    // Matrix Multiplication logic to reverse the scrambling
    assign col_out[31:24] = gf_mul_e(s3) ^ gf_mul_b(s2) ^ gf_mul_d(s1) ^ gf_mul9(s0);
    assign col_out[23:16] = gf_mul9(s3) ^ gf_mul_e(s2) ^ gf_mul_b(s1) ^ gf_mul_d(s0);
    assign col_out[15:8]  = gf_mul_d(s3) ^ gf_mul9(s2) ^ gf_mul_e(s1) ^ gf_mul_b(s0);
    assign col_out[7:0]   = gf_mul_b(s3) ^ gf_mul_d(s2) ^ gf_mul9(s1) ^ gf_mul_e(s0);
endmodule