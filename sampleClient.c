#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>

#define CUSTOM_VERIFICATION_CALLBACK

// added by junjinyong on 2023.11.21
#include <openssl/x509_vfy.h>
#include <curl/curl.h>
#include <openssl/pem.h>

enum STATE {
    REVOKED = -1,
    CRL_NOT_FOUND = 0,
    VALIDATED = 1,
};


char* convert(const ASN1_TIME* asn1_time) {
    struct tm time;
    ASN1_TIME_to_tm(asn1_time, &time);
    char* buff = (char*) malloc(20 * sizeof(char)); // must be freed later
    strftime(buff, 20, "%Y.%m.%d %H:%M", &time);
    return buff;
}

// TODO: Callback function for custom certificate verification
#ifndef CUSTOM_VERIFICATION_CALLBACK
// Default certificate verfication function
int (*verify_callback)(int preverify, X509_STORE_CTX *ctx) = NULL;
#else

char str[1048576];

// Custom certificate verification function
int verify_callback(int preverify, X509_STORE_CTX* ctx) {
    const int depth = X509_STORE_CTX_get_error_depth(ctx);
    const int err = X509_STORE_CTX_get_error(ctx);
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

    char subject_str[256];
    char issuer_str[256];

    X509_NAME *subject_name = X509_get_subject_name(cert);
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));
    X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));

    sprintf(str + strlen(str), "Certificate at depth: %d\n", depth);
    sprintf(str + strlen(str), "Subject: %s\n", subject_str);
    sprintf(str + strlen(str), "Issuer: %s\n\n", issuer_str);

    if (!preverify) {
        printf("%s", str);

        switch (err) {
            // Not yet valid certificate
            case X509_V_ERR_CERT_NOT_YET_VALID:
                const ASN1_TIME* not_before = X509_get_notBefore(cert);
                char* buff1 = convert(not_before);
                fprintf(stderr, "Certificate at depth %d is valid from %s\n", depth, buff1);
                free(buff1);
                break;
            // Expired certificate
            case X509_V_ERR_CERT_HAS_EXPIRED:
                const ASN1_TIME* not_after = X509_get_notAfter(cert);
                char* buff2 = convert(not_after);
                fprintf(stderr, "Certificate at depth %d has expired on %s\n", depth, buff2);
                free(buff2);
                break;
            // Certificate signature failure
            case X509_V_ERR_CERT_SIGNATURE_FAILURE:
                fprintf(stderr, "Certificate signature failed at depth %d\n", depth);
                break;
            // Unable to get local issuer certificate
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                fprintf(stderr, "Unable to get local issuer certificate at depth %d\n", depth);
                break;
            // Unable to get certificate CRL
            case X509_V_ERR_UNABLE_TO_GET_CRL:
                fprintf(stderr, "Unable to get certificate CRL at depth %d\n", depth);
                break;
            // No trusted root certificate
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                fprintf(stderr, "No trusted root certificate at depth %d\n", depth);
                break;
            // Unable to get local issuer certificate
            case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
                fprintf(stderr, "Unable to get local issuer certificate at depth %d\n", depth);
                break;
            default:
                break;
        }

        fprintf(stderr, "Certificate verification failed at depth %d with error %d: %s\n",
                depth, err, X509_verify_cert_error_string(err));

        return 0;
    }

    return preverify;
}
#endif

int check(X509 *cert) {
    FILE* fp = fopen("cert.crl", "rb");
    if (fp == NULL) {
        return CRL_NOT_FOUND;
    }

    X509_CRL *crl = d2i_X509_CRL_fp(fp, NULL);
    fclose(fp);
    if(crl == NULL) {
        printf("Hello from check\n");
        return CRL_NOT_FOUND;
    }

    const ASN1_INTEGER* serial = X509_get_serialNumber(cert);

    STACK_OF(X509_REVOKED)* list = X509_CRL_get_REVOKED(crl);
    const int number = sk_X509_REVOKED_num(list);
    printf("number: %d\n\n", number);
    for (int i = 0; i < number; ++i) {
        const X509_REVOKED* revoked = sk_X509_REVOKED_value(list, i);
        const ASN1_INTEGER* revoked_serial = X509_REVOKED_get0_serialNumber(revoked);
        if (ASN1_INTEGER_cmp(serial, revoked_serial) == 0) {
            return REVOKED;
        }
    }

    return VALIDATED;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(contents, size, nmemb, stream);
}

int download_CRL(const unsigned char* addr) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL* curl = curl_easy_init();
    if (curl == NULL) {
        return 0;
    }

    FILE* fp = fopen("cert.crl", "wb");
    if (fp == NULL) {
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_URL, addr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    if (res != CURLE_OK) {
        return 0;
    }
    curl_easy_cleanup(curl);

    return 1;
}

int check_CRL(X509 *cert) {
    STACK_OF(DIST_POINT)* dp_stack = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (dp_stack == NULL) {
        return 0;
    }

    const int number = sk_DIST_POINT_num(dp_stack);
    int flag = CRL_NOT_FOUND;
    for (int i = 0; i < number; ++i) {
        DIST_POINT* dp = sk_DIST_POINT_value(dp_stack, i);
        if (dp == NULL || (dp -> distpoint) == NULL) {
            continue;
        }

        GENERAL_NAMES* names = (dp -> distpoint -> name).fullname;
        if (names == NULL) {
            continue;
        }

        const int count = sk_GENERAL_NAME_num(names);
        for (int j = 0; j < count; ++j) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);
            if (name == NULL || (name -> type != GEN_URI)) {
                continue;
            }

            const unsigned char* addr = (name -> d).uniformResourceIdentifier -> data;
            if (download_CRL(addr) == 0) {
                continue;
            }

            printf("CRL distribution point: %s\n", addr);
            if (check(cert) != REVOKED && flag != REVOKED) {
                flag = VALIDATED;
            } else {
                flag = REVOKED;
            }
        }

    }

    return flag;
}


void print_certificate(X509 *cert) {
    if (cert) {
        printf("Certificate:\n");
        X509_print_fp(stdout, cert);
        printf("\n");
    }
}

void print_certificate_info(X509 *cert, int depth) {
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME *issuer = X509_get_issuer_name(cert);

    char subj_str[256];
    char issuer_str[256];

    // Convert the names to a readable string
    X509_NAME_oneline(subj, subj_str, sizeof(subj_str));
    X509_NAME_oneline(issuer, issuer_str, sizeof(issuer_str));

    // Print the certificate details at the given depth
    printf("Certificate at depth: %d\n", depth);
    printf("Subject: %s\n", subj_str);
    printf("Issuer: %s\n\n", issuer_str);
}

void save_certificate(X509 *cert, const char *filename) {
    if (cert) {
        FILE *fp = fopen(filename, "w");
        if (fp) {
            PEM_write_X509(fp, cert);
            fclose(fp);
            printf("Saved certificate to %s\n", filename);
        } else {
            fprintf(stderr, "Could not open %s for writing.\n", filename);
        }
    }
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    X509 *cert;
    STACK_OF(X509) *cert_chain;
    int option;
    int verbose = 0, output_files = 0;

    while ((option = getopt(argc, argv, "vo")) != -1) {
        switch (option) {
            case 'v': verbose = 1; break;
            case 'o': output_files = 1; break;
            default: fprintf(stderr, "Invalid option\n");
                     exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-v|-o] <host>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *host = argv[optind];

    // Initialize OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings(); // Deprecated: Error strings are loaded automatically since OpenSSL 1.1.0.
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // TODO: Set the location of the trust store. Currently based on Debian.
    // Done
    if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) {
        fprintf(stderr, "Error setting up trust store.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // TODO: automatic chain verification should be modified
    // Done
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);


    // Create a new BIO chain with an SSL BIO using the context
    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set up the SSL
    BIO_get_ssl(bio, &ssl);
    if (ssl == NULL) {
        fprintf(stderr, "Error getting SSL.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set the SNI hostname
    SSL_set_tlsext_host_name(ssl, host);

    // Set up the connection to the remote host
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_port(bio, "443");

    // Enable OCSP stapling
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

    // Attempt to connect
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to remote host.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Attempt to do the TLS/SSL handshake
    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    long verification_result = SSL_get_verify_result(ssl);
    if (verification_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %ld (%s)\n",
                verification_result, X509_verify_cert_error_string(verification_result));
    }

    // Check for stapled OCSP response
    const unsigned char *ocsp_resp;
    long ocsp_resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_resp);
    OCSP_RESPONSE *response = NULL;

    if (ocsp_resp_len > 0) {
        printf("OCSP response is stapled.\n");
        
        // Decode the OCSP response
        const unsigned char *p = ocsp_resp; // temporary pointer
        response = d2i_OCSP_RESPONSE(NULL, &p, ocsp_resp_len);
        if (response) {
            if (verbose) {
                OCSP_RESPONSE_print(BIO_new_fp(stdout, BIO_NOCLOSE), response, 0);
            }
            
            if (output_files) {
                // Save the OCSP response to a file
                FILE *fp = fopen("ocsp.pem", "wb");
                if (fp != NULL) {
                    const int length = i2d_OCSP_RESPONSE(response, NULL);
                    if (length > 0) {
                        unsigned char *der = malloc(length);
                        unsigned char *p = der;
                        if (i2d_OCSP_RESPONSE(response, &p) > 0) {
                            fwrite(der, 1, length, fp);
                            printf("OCSP response saved to ocsp.pem\n");
                        } else {
                            fprintf(stderr, "Error converting OCSP response to DER format.\n");
                        }
                        free(der);
                    } else {
                        fprintf(stderr, "Error determining OCSP response length.\n");
                    }
                    fclose(fp);
                } else {
                    fprintf(stderr, "Unable to open ocsp.pem for writing.\n");
                }
            }
            OCSP_RESPONSE_free(response);
        } else {
            fprintf(stderr, "Failed to decode OCSP response.\n");
        }
    } else {
        printf("No OCSP stapling response received.\n");
    }

    // Retrieve the certificate chain
    cert_chain = SSL_get_peer_cert_chain(ssl);
    if (cert_chain == NULL) {
        fprintf(stderr, "Error getting certificate chain.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Print details for each certificate in the chain
    int flag = 0;
    for (int i = 0; i < sk_X509_num(cert_chain); i++) {
        cert = sk_X509_value(cert_chain, i);
        if (verbose) {
            print_certificate(cert);
        } else {
        // For non-verbose, print simplified information
        print_certificate_info(cert, i);
        }
        if (output_files) {
            char filename[32];
            snprintf(filename, sizeof(filename), "depth%d.pem", i);
            save_certificate(cert, filename);
        }
        // TODO: Get CRL distribution points and OCSP responder URI
        if (i == 0) {
            flag = check_CRL(cert);
        }
    }

    if (flag == CRL_NOT_FOUND) {
        fprintf(stderr, "No certificate distribution point found at depth 0\n");
    } else if (flag == REVOKED) {
        fprintf(stderr, "Certificate is revocated at depth 0\n");
    } else if (flag == VALIDATED) {
        printf("Certificate is not revocated at level 0\n");
    }

    // Clean up
    ERR_clear_error();
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
