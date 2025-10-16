#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "optimized_super_duper_allocator.h"    // so fucking optimized that it doesn't even overwrite freed bytes 
#include "damn_crypto_magic.h"                  // do not try this at home — just trust; though you can check the disassembled binary, just to be sure 🤡

#define BUF_SIZE 512

typedef struct {
    char* data;
    char checksum;
    int data_destructed;
} secure_drive_t;

typedef struct {
    char first_code[32];
    char second_code[32];
    int access_approved;
    int destruct_activated;
} auth_system_t;

typedef struct {
    char operation_buffer[32];
    int integrity_validator;
    char system_cache[5][16];
    volatile int operation_done;
} memory_operation_t;

typedef struct {
    volatile int memory_anomaly;
    volatile int access_violation;
    volatile int data_remnant;
    char anomaly_signature[32];
    char violation_pattern[32];
    memory_operation_t* active_operation;
    char* op_info_data;
} security_audit_t;

secure_drive_t phone_drive;
auth_system_t auth;
security_audit_t audit;
unsigned int session_id;

void init_system() {
    session_id = time(NULL) ^ getpid();
    srand(session_id);

    init_free_list();

    phone_drive.data = allocate(BUF_SIZE);
    phone_drive.checksum = 0;
    phone_drive.data_destructed = 0;
    
    auth.access_approved = 0;
    auth.destruct_activated = 0;

    memset(&audit, 0, sizeof(audit));
    audit.active_operation = NULL;
    audit.op_info_data = NULL;

    const char* secret_data = "473B76A268F2DC1212E721F5088544D900689F4661EF2C443F2A889C696ED846";
    
    strncpy(phone_drive.data, secret_data, BUF_SIZE - 1);
    phone_drive.data[BUF_SIZE - 1] = 0;

    for (int i = 0; i < BUF_SIZE; i++) {
        phone_drive.checksum ^= phone_drive.data[i];
    }

    for (int i = 0; i < 17; i++) {
        auth.first_code[i] = 'A' + (rand() % 26);
    }
    auth.first_code[17] = 0;
    
    for (int i = 0; i < 12; i++) {
        auth.second_code[i] = 'a' + (rand() % 26);
    }
    auth.second_code[12] = 0;
}

memory_operation_t* setup_memory_operations() {
    memory_operation_t* op = allocate(sizeof(memory_operation_t));
    if (!op) return NULL;
    
    op->integrity_validator = 1;
    op->operation_done = 0;
    
    for (int i = 0; i < 5; i++) {
        memset(op->system_cache[i], 0xCC + i, 16);
    }
    
    return op;
}

void process_system_input(char* user_input, int input_size) {
    if (!audit.active_operation) {
        audit.active_operation = setup_memory_operations();
        if (!audit.active_operation) return;
    }
    
    memcpy(audit.active_operation->operation_buffer, user_input, input_size);

    audit.active_operation->operation_done = 1;
}

void memory_audit() {
    if (!audit.active_operation) return;
    
    if (audit.active_operation->integrity_validator == 0x52454853) {
        audit.memory_anomaly = 1;
        snprintf(audit.anomaly_signature, 32, "MEM_ANOMALY_%08x", audit.active_operation->integrity_validator);
    }
    
    if (audit.active_operation) {
        release(audit.active_operation);
        audit.active_operation = NULL;
    }
}

void check_op_info() {
    if (audit.op_info_data != NULL) {
        char info[BUF_SIZE];
        memcpy(info, audit.op_info_data, BUF_SIZE);
        
        if (strlen(info) > 0) {
            audit.data_remnant = 1;
        }
    }
}

void analyze_memory_access_patterns(char* user_input) {
    if (strlen(user_input) > 32) {
        audit.access_violation = 1;
        unsigned int access_token = 0xDEADBEEF;
        snprintf(audit.violation_pattern, 32, "ACCESS_VIOL_%08x", access_token);
    }
}

void log_system_info() {
    const char* alert = "473B76A268F2DC1212E721F5088544D927A9BBEF61B15D09C50DA562628C3513";
    char* info = decrypt(alert);
    printf("[ALERT] %s\n", info);
    free(info);
}

void authentication(char* first_input, char* second_input) {
    if (strncmp(first_input, auth.first_code, 17) == 0) {
        auth.access_approved = 1;
        printf("[+] Access code accepted\n");
    } else {
        printf("[-] Invalid access code\n");
    }
    
    if (strcmp(second_input, auth.second_code) == 0) {
        auth.destruct_activated = 1;
        printf("[!] Destruct code verified\n");
        
        if (!phone_drive.data_destructed) {
            audit.op_info_data = phone_drive.data;
            release(phone_drive.data);
            phone_drive.data = NULL;
            phone_drive.data_destructed = 1;
            printf("[!] Drive data destroyed - memory released\n");
        }
    }
}

int evaluate_security_status() {
    if (audit.memory_anomaly && 
        audit.access_violation && 
        audit.data_remnant) {
        return 0;
    } else {
        return 1;
    }
}

void display_security_alert() {
    if (!evaluate_security_status()) {
        printf("[!] You were very observant. I'm flattered.\n");
        log_system_info();
    } else {
        printf("[✓] All security systems are operating normally.\n");    
    }
}

void perform_system_diagnostics() {
    printf("\n[SYSTEM] Running comprehensive diagnostics...\n");
    memory_audit();
    display_security_alert();
}

void access_secure_data() {
    if (!auth.access_approved) {
        printf("[-] Access denied\n");
        return;
    }
    
    if (auth.destruct_activated) {
        printf("[-] Destruction activated - access blocked\n");
        return;
    }
    
    printf("[+] Secure data accessed\n");
    if (!phone_drive.data_destructed) {
        char* decrypted_data = decrypt(phone_drive.data);
        printf("%s\n", decrypted_data);
        free(decrypted_data);
    }
}

int main() {
    char code1[BUF_SIZE];
    char code2[BUF_SIZE];
    int attempts = 0;

    printf("Initializing secure phone system...\n\n");
    init_system();
    
    printf("=== SECURE PHONE SYSTEM ===\n");
    printf("Dual-passcode authentication required\n");
    printf("Session ID: %08x\n\n", session_id);
    
    while (attempts < 2) {
        printf("Attempt %d/2\n", attempts + 1);
        
        printf("Enter the first code: ");
        if (!fgets(code1, sizeof(code1), stdin)) break;
        code1[strcspn(code1, "\n")] = 0;
        
        printf("Enter the second code: ");
        if (!fgets(code2, sizeof(code2), stdin)) break;
        code2[strcspn(code2, "\n")] = 0;
        printf("\n");
        
        process_system_input(code1, strlen(code1));
        analyze_memory_access_patterns(code1);
        authentication(code1, code2);
        
        if (auth.access_approved && !auth.destruct_activated) {
            printf("[+] Authentication successful!\n");
            access_secure_data();
            break;
        } else {
            attempts++;
            if(attempts == 1) {
                check_op_info();
                printf("[!] One attempt remaining - security protocols engaged\n");
            }
        }
        printf("\n");
    }
    
    if (attempts >= 2) {
        printf("[!] Maximum authentication attempts exceeded\n");
        printf("[!] System locked\n");
    }

    perform_system_diagnostics();
    printf("\nSystem shutdown complete\n");

    return 0;
}

