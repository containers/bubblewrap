#include "destinations-graph.h"

DestinationsLinkedList *
DestinationsLinkedList_create (void)
{
  DestinationsLinkedList *list = xcalloc(1, sizeof (DestinationsLinkedList));
  list->head = NULL;
  list->tail = NULL;
  list->count = 0;
  return list;
}

void
DestinationsLinkedList_free (DestinationsLinkedList *self)
{
  DestinationsLinkedList_Node *current = self->head;

  while (current != NULL)
    {
      DestinationsLinkedList_Node *next = current->next;
      free (current);
      current = next;
    }

  free (self);
}

void
DestinationsLinkedList_push_back (DestinationsLinkedList *self,
                                  DestinationsGraph_Node *node)
{

  DestinationsLinkedList_Node *pushed = xcalloc(1, sizeof (DestinationsLinkedList_Node));
  pushed->value = node;
  pushed->next = NULL;

  // If they NULL, then only both
  if (self->head == NULL || self->tail == NULL)
    {
      self->head = pushed;
      self->tail = pushed;
      self->count = 1;
    }
  else
    {
      self->tail->next = pushed;
      self->tail = self->tail->next;
    }
}

DestinationsGraph_Node*
DestinationsLinkedList_find_by_path_part (DestinationsLinkedList *self,
                                          char *path_part)
{
  DestinationsLinkedList_Node *current = self->head;

  while (current != NULL)
    {
      if(strcmp (current->value->path_part, path_part) == 0)
        return current->value;
      current = current->next;
    }
  return NULL;
}
