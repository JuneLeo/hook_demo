//
// Created by juneleo on 2024/1/13.
//

#ifndef ELF_CALL_PERSON_H
#define ELF_CALL_PERSON_H
#include <string>


class person {
public:
    std::string name;
    int64_t age;

    void play();

private:

    void grow();

};


#endif //ELF_CALL_PERSON_H
