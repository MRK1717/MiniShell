#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MAX_RETURNS 1000

// Funcție pentru compararea valorilor (pentru qsort)
int cmpfunc (const void * a, const void * b) {
    double diff = (*(double*)a) - (*(double*)b);
    return (diff < 0) ? -1 : (diff > 0) ? 1 : 0;
}

// Citirea datelor din fișierul CSV (un return pe linie)
int load_returns(const char *filename, double returns[], int *n) {
    FILE *file = fopen(filename, "r");
    if (!file) return 0; // Nu a putut fi deschis

    char line[128];
    *n = 0;
    while (fgets(line, sizeof(line), file) && *n < MAX_RETURNS) {
        returns[(*n)++] = atof(line);
    }
    fclose(file);
    return 1;
}

// Generarea de date de test și salvarea într-un CSV
void generate_sample_data(const char *filename, int n) {
    FILE *file = fopen(filename, "w");
    if (!file) return;
    srand(42);
    for (int i = 0; i < n; i++) {
        // Generare de date random, distribuție normală simplificată
        double r = ((double)rand() / RAND_MAX - 0.5) * 0.04; // Aproximativ între -0.02 și 0.02
        fprintf(file, "%.6f\n", r);
    }
    fclose(file);
    printf("Sample data created in '%s'.\n", filename);
}

// Calculul Value-at-Risk (VaR)
double compute_var(double returns[], int n, double confidence_level) {
    // Sortăm array-ul
    qsort(returns, n, sizeof(double), cmpfunc);
    int index = (int)((1 - confidence_level) * n);
    return returns[index];
}

// Calculul Sharpe Ratio
double compute_sharpe_ratio(double returns[], int n, double risk_free_rate) {
    double sum = 0.0, sumsq = 0.0;
    for (int i = 0; i < n; i++) {
        double excess = returns[i] - risk_free_rate;
        sum += excess;
        sumsq += excess * excess;
    }
    double mean = sum / n;
    double stddev = sqrt((sumsq / n) - (mean * mean));
    return (stddev != 0) ? mean / stddev : 0;
}

int main() {
    const char *csv_file = "sample_returns.csv";
    double returns[MAX_RETURNS];
    int n = 0;
    
    if (!load_returns(csv_file, returns, &n)) {
        // Dacă fișierul nu există, generăm date de test
        generate_sample_data(csv_file, 1000);
        load_returns(csv_file, returns, &n);
    }

    double var = compute_var(returns, n, 0.95);
    double sharpe = compute_sharpe_ratio(returns, n, 0.0);

    printf("Value-at-Risk (VaR): %.6f\n", var);
    printf("Sharpe Ratio: %.6f\n", sharpe);

    return 0;
}
