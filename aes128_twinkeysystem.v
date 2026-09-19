\\TWIN KEY SYSTEM


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