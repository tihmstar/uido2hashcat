//
//  main.cpp
//  uido2hashcat
//
//  Created by tihmstar on 02.07.21.
//

#include <libgeneral/macros.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <plist/plist.h>
#include <string.h>
#include <arpa/inet.h>

plist_t readPlistFromFile(const char *filePath){
    int fd = -1;
    char *buf = NULL;
    cleanup([&]{
        safeFree(buf);
        safeClose(fd);
    });
    struct stat st = {};
    retassure((fd = open(filePath, O_RDONLY)) > 0, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    
    retassure(buf = (char*)malloc(st.st_size),"Failled to malloc");
    retassure(read(fd, buf, st.st_size) == st.st_size, "Failed to read file");
    
    {
        plist_t plist = NULL;
        plist_from_memory(buf, (uint32_t)st.st_size, &plist);
        return plist;
    }
}

size_t parseHex(const char *hexStr, uint8_t *outBuf, size_t outBufSize){
    size_t i = 0;
    for (i=0; i<strlen(hexStr); i+=2) {
        unsigned int b;
        retassure(i/2<outBufSize, "hexStr key too long");
        retassure(sscanf(&hexStr[i], "%02x",&b) == 1, "failed to parse hexStr");
        outBuf[i/2] = (uint8_t)b;
    }
    return i;
}

#define MAX_CLASS_KEYS                      20
struct ClassKey{
    unsigned char uuid[16];
    unsigned int clas;
    unsigned int wrap;
    unsigned char wpky[40];
};
struct KeyBag{
    unsigned int version;
    unsigned int type;
    unsigned char uuid[16];
    unsigned char hmck[40];
    unsigned char salt[20];
    unsigned int iter;
    unsigned int numKeys;
    struct ClassKey keys[MAX_CLASS_KEYS];
};
struct KeyBagBlobItem{
    unsigned int tag;
    unsigned int len;
    union{
        unsigned int intvalue;
        unsigned char bytes[1];
    } data;
};

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s", VERSION_STRING);
    const char *uid_key_str = NULL;
    const char *kbdumpPath = NULL;
    KeyBag kb{};
    uint8_t uid[0x10]{}; //128bit AES

    if (argc < 3) {
        info("uido2hashcat: <uid key hex> <kbdump path>\n");
        return -1;
    }
        
    {
        uid_key_str = argv[1];
        for (int i=0; i<strlen(uid_key_str); i+=2) {
            unsigned int b;
            retassure(i/2<sizeof(uid), "UID key too long");
            retassure(sscanf(&uid_key_str[i], "%02x",&b) == 1, "failed to parse UID key");
            uid[i/2] = (uint8_t)b;
        }
    }

    kbdumpPath = argv[2];

    
    //parse keybag
    {
        plist_t p_keybag = NULL;
        char *keybagdata = NULL;
        cleanup([&]{
            safeFree(keybagdata);
            safeFreeCustom(p_keybag, plist_free);
        });
        uint64_t keybagdataLen = 0;
        plist_t p_keybagKeys = NULL;

        retassure(p_keybag = readPlistFromFile(kbdumpPath),"failed to read keybagdump");

        {
            // uuid
            plist_t p_uuid = NULL;
            const char *str = NULL;
            uint64_t strlen = 0;
            retassure(p_uuid = plist_dict_get_item(p_keybag, "uuid"),"failed to read uuid");
            retassure(plist_get_node_type(p_uuid) == PLIST_STRING, "uuid is not string");
            retassure(str = plist_get_string_ptr(p_uuid, &strlen), "Failed to get str ptr");
            parseHex(str, kb.uuid, sizeof(kb.uuid));
        }
        
        {
            // salt
            plist_t p_salt = NULL;
            const char *str = NULL;
            uint64_t strlen = 0;
            retassure(p_salt = plist_dict_get_item(p_keybag, "salt"),"failed to read salt");
            retassure(plist_get_node_type(p_salt) == PLIST_STRING, "salt is not string");
            retassure(str = plist_get_string_ptr(p_salt, &strlen), "Failed to get str ptr");
            parseHex(str, kb.salt, sizeof(kb.salt));
        }
        
        // KeyBagKeys
        retassure(p_keybagKeys = plist_dict_get_item(p_keybag, "KeyBagKeys"),"failed to read KeyBagKeys");
        retassure(plist_get_node_type(p_keybagKeys) == PLIST_DATA, "KeyBagKeys is not data");
        plist_get_data_val(p_keybagKeys, &keybagdata, &keybagdataLen);
        retassure(keybagdata, "Failed to get keybag data");

        // AppleKeyStore_parseBinaryKeyBag //https://github.com/dinosec/iphone-dataprotection/blob/master/ramdisk_tools/AppleKeyStore.c#L270
        {
            struct KeyBagBlobItem* p = NULL;
            const uint8_t* end = NULL;
            int kbuuid=0;
            int i = -1;
            p = (struct KeyBagBlobItem*) keybagdata;
            retassure(p->tag == 'ATAD',"Keybag does not start with DATA");
            retassure((8 + htonl(p->len) <= keybagdataLen),"Bad length");
            end = (uint8_t*)keybagdata + 8 + htonl(p->len);
            p = (struct KeyBagBlobItem*) p->data.bytes;
            while ((uint8_t*)p < end) {
                uint64_t len = htonl(p->len);

                if (p->tag == 'SREV') kb.version = htonl(p->data.intvalue);
                else if (p->tag == 'EPYT') kb.type = htonl(p->data.intvalue);
                else if (p->tag == 'TLAS') memcpy(kb.salt, p->data.bytes, 20);
                else if (p->tag == 'RETI') kb.iter = htonl(p->data.intvalue);
                else if (p->tag == 'DIUU') {
                    if (!kbuuid){
                        memcpy(kb.uuid, p->data.bytes, 16);
                        kbuuid = 1;
                    }
                    else{
                        i++;
                        if (i >= MAX_CLASS_KEYS)
                            break;
                        memcpy(kb.keys[i].uuid, p->data.bytes, 16);
                    }
                }
                else if (p->tag == 'SALC') kb.keys[i].clas = htonl(p->data.intvalue);
                else if (p->tag == 'PARW' && kbuuid) kb.keys[i].wrap = htonl(p->data.intvalue);
                else if (p->tag == 'YKPW') memcpy(kb.keys[i].wpky, p->data.bytes, (len > 40)  ? 40 : len);
                p = (struct KeyBagBlobItem*) &p->data.bytes[len];
            }
            kb.numKeys = i + 1;
        }
    }

    /*
     print output:
     */
    info("hashcat format: ($uido$<UID key>$<salt>$<itercount>$<classkey1>$<classkey2> etc...)");
    //uido
    printf("$uido$");
    //UID key
    for (int i=0; i<sizeof(uid); i++) {
        printf("%02x",uid[i]);
    }
    printf("$");
    //salt
    for (int i=0; i<sizeof(kb.salt); i++) {
        printf("%02x",kb.salt[i]);
    }
    //iter
    printf("$%u",kb.iter);
    //class keys
    for (int i=0; i < kb.numKeys; i++){
        if (kb.keys[i].wrap & 2){
            //only print classkeys which need unwrapping!
            printf("$");
            for (int j=0; j<sizeof(kb.keys[0].wpky); j++) {
                printf("%02x",kb.keys[i].wpky[j]);
            }
        }
    }
    printf("\n");
    
    return 0;
}
