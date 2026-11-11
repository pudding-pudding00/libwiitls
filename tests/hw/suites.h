/* Suites the hardware runner knows. Each later task declares its suite here
 * and adds its {name, fn} row to suites.inc. */
#ifndef WTLS_HW_SUITES_H
#define WTLS_HW_SUITES_H

void wtls_suite_spike(void);
void wtls_suite_entropy(void);
void wtls_suite_plat(void);
void wtls_suite_time(void);

#endif
