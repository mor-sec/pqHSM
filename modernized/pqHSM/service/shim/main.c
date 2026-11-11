/* pqhsm-service's main: everything else is the Rust staticlib (analysis/pqHSM/PHASE6_PLAN.md). */
int pqhsm_service_main(int argc, char **argv);

int main(int argc, char **argv)
{
    return pqhsm_service_main(argc, argv);
}
