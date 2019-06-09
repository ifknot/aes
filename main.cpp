#define CATCH_CONFIG_RUNNER
#include "tests/catch2.h"

int main( int argc, char* argv[] ) {

    // https://github.com/ifknot/Catch2
    return Catch::Session().run( argc, argv );

}
