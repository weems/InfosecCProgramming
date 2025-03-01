#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <time.h>

// Structure to hold response time and SSL details
typedef struct {
    double total_time;
    char *cert_issuer;
    char *cert_start;
    char *cert_expiry;
} PageInfo;

// Callback function for libcurl to discard received data
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    (void)contents; // Prevent unused variable warning
    return size * nmemb;
}

// Function to fetch and display page info
void fetch_page_info(const char *url) {
    CURL *curl;
    CURLcode res;
    PageInfo page_info = {0};

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Enable retrieving SSL certificate details
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    // Perform request
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // Get time taken for the request
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &page_info.total_time);

        // Get SSL certificate details
        struct curl_certinfo *ci;
        if (curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci) == CURLE_OK && ci->num_of_certs > 0) {
            X509 *cert = d2i_X509(NULL, (const unsigned char **)&ci->certinfo[0].data, ci->certinfo[0].len);
            if (cert) {
                X509_NAME *issuer = X509_get_issuer_name(cert);
                char issuer_name[256];
                X509_NAME_oneline(issuer, issuer_name, sizeof(issuer_name));
                page_info.cert_issuer = strdup(issuer_name);
                
                ASN1_TIME *start = X509_get_notBefore(cert);
                ASN1_TIME *end = X509_get_notAfter(cert);
                page_info.cert_start = strdup((char *)ASN1_STRING_data(start));
                page_info.cert_expiry = strdup((char *)ASN1_STRING_data(end));
                X509_free(cert);
            }
        }

        // Print Results
        time_t rawtime;
        struct tm *timeinfo;
        char timestamp[80];
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(timestamp, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
        
        printf("Timestamp: %s\n", timestamp);
        printf("Page Load Time: %.2f seconds\n", page_info.total_time);
        printf("URL: %s\n", url);
        printf("SSL Certificate Issuer: %s\n", page_info.cert_issuer ? page_info.cert_issuer : "Unknown");
        printf("SSL Start Date: %s\n", page_info.cert_start ? page_info.cert_start : "Unknown");
        printf("SSL Expiry Date: %s\n", page_info.cert_expiry ? page_info.cert_expiry : "Unknown");
    } else {
        fprintf(stderr, "Failed to fetch URL: %s\n", curl_easy_strerror(res));
    }

    // Cleanup
    curl_easy_cleanup(curl);
    free(page_info.cert_issuer);
    free(page_info.cert_start);
    free(page_info.cert_expiry);
}

int main() {
    char url[256];
    printf("Enter URL: ");
    scanf("%255s", url);
    fetch_page_info(url);
    return 0;
}
