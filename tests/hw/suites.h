/* Suites the hardware runner knows. Each later task appends its suite here. */
#ifndef WTLS_HW_SUITES_H
#define WTLS_HW_SUITES_H

void wtls_suite_spike(void);
void wtls_suite_entropy(void);
void wtls_suite_plat(void);

/* Extra {name, fn} rows for the runner's suite table. */
#define WTLS_HW_SUITES \
    {"entropy", wtls_suite_entropy}, \
    {"plat", wtls_suite_plat},

#endif
