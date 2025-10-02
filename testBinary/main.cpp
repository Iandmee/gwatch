#include <iostream>

int variable = 26;
int main() {

    std::cout << variable << std::endl;
    ++variable;
    ++variable;
    long long b = variable;
    ++variable;
    std::cout << b << std::endl;
    int &c = variable;
    std::cout << ++c << std::endl;
    for (; variable > 0; --variable) {
        std::cout << variable << std::endl;
    }
    return 0;
}