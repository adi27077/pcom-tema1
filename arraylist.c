#include <stdlib.h>
#include <string.h>

#include "arraylist.h"
#include "../debug/fatal.h"


#define DEFAULT_CAPACITY 1

struct arraylist {
    void *_info;
    size_t _el_size;
    size_t _capacity;
    size_t _size;
};

arraylist_t *create_list(size_t el_size)
{
    arraylist_t *list = calloc(1, sizeof(arraylist_t));

    if (!list)
        return NULL;

    list->_el_size = el_size;
    list->_capacity = DEFAULT_CAPACITY;

    list->_info = calloc(list->_capacity, el_size);

    if (!list->_info) {
        free(list);
        return NULL;
    }

    return list;
}

void push(arraylist_t *list, void *info)
{
    if (list->_capacity == list->_size) {
        void *resized_info = realloc(list->_info, 2 * list->_el_size * list->_capacity);

        if (!resized_info)
            FATAL_ERROR("List resize fail.");

        list->_info = resized_info;
        list->_capacity *= 2;
    }
    memcpy(list->_info + list->_el_size * list->_size, info, list->_el_size);
    list->_size++;
}

size_t size(const arraylist_t *list)
{
    return list->_size;
}

void *get(const arraylist_t *list, int index)
{
    if (index >= list->_capacity)
        return NULL;
    else
        return list->_info + list->_el_size * index;
}

void set(arraylist_t *list, int index, void *info)
{
    if (index >= list->_capacity)
        FATAL_ERROR("Index out of range.");
    else
        memcpy(list->_info + list->_el_size * index, info, list->_el_size);
}

void flush(arraylist_t *list)
{
    list->_size = 0;
}

void destroy_list(arraylist_t **list)
{
    free((*list)->_info);
    (*list)->_info = NULL;
    free(*list);
    *list = NULL;
}