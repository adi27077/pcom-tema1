#ifndef __ARRAYLIST__
#define __ARRAYLIST__

#include <stdio.h>


typedef struct arraylist arraylist_t;

/*
 * Create an arraylist.
 * @params: el_size -> size of the elements contained by the arraylist
 * @returns: newly allocated arraylist object
 */
arraylist_t *create_list(size_t el_size);

/*
 * Add an element to the arraylist.
 * @params: list -> pointer to an arraylist object
 *          info -> pointer to the element to be added
 * @returns: no return
 */
void push(arraylist_t *list, void *info);

/*
 * Flush / clear the arraylist.
 * @params: list -> pointer to an arraylist object
 * @returns: no return
 */
void flush(arraylist_t *list);

/*
 * Safe delete an arraylist object.
 * @params: list -> reference of pointer to an arraylist object
 * @returns: no return
 */
void destroy_list(arraylist_t **list);

/*
 * Get the size of the arraylist.
 * @params: list -> pointer to an arraylist object.
 * @returns: size of the arraylist
 */
size_t size(const arraylist_t *list);

/*
 * Retrieve an element found at given index.
 * @params: list -> pointer to an arraylist object.
 *          index -> position of the searched element
 * @returns: pointer to searched element
 */
void *get(const arraylist_t *list, int index);

/*
 * Set the value of an element found at given position.
 * @params: list -> pointer to an arraylist object.
 *          index -> position of the searched element
 *          info -> the new value
 * @returns: no return
 */
void set(arraylist_t *list, int index, void *info);

#endif