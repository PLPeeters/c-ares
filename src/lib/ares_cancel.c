/* MIT License
 *
 * Copyright (c) 2004 Daniel Stenberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_private.h"

/*
 * ares_cancel() cancels all ongoing requests/resolves that might be going on
 * on the given channel. It does NOT kill the channel, use ares_destroy() for
 * that.
 */
void ares_cancel(ares_channel_t *channel)
{
  if (channel == NULL) {
    return;
  }

  ares_channel_lock(channel);
  ares_deferred_cb_enter(channel);

  if (ares_llist_len(channel->all_queries) > 0) {
    ares_llist_node_t *node = NULL;

    /* Move the current queries to the cancellation list, so that only those
     * queries which were present on entry into this function are cancelled.
     * New queries added by callbacks of queries being cancelled will not be
     * cancelled themselves unless a callback calls ares_cancel() again.
     */
    while ((node = ares_llist_node_first(channel->all_queries)) != NULL) {
      ares_llist_node_mvparent_last(node, channel->queries_being_cancelled);
    }

    /* Re-read the head each iteration rather than caching the next node: a
     * callback below may cause other queries in this same list to be ended
     * and their nodes destroyed. */
    while ((node = ares_llist_node_first(channel->queries_being_cancelled)) !=
           NULL) {
      ares_query_t *query;

      query = ares_llist_node_claim(node);

      /* Must come first: node_claim() already destroyed this node, so
       * ares_detach_query() would otherwise destroy it a second time. */
      query->node_all_queries = NULL;

      /* Detach from queries_by_qid, the connection and the timeout list
       * before running user code.  Otherwise a reentrant teardown from
       * within the callback -- ares_set_servers_csv(), or a new query
       * hitting a connection error -- still finds this query, ends it a
       * second time and frees it, and the ares_free_query() below then
       * double-frees. */
      ares_detach_query(query);

      /* NOTE: its possible this may enqueue new queries */
      query->callback(query->arg, ARES_ECANCELLED, 0, NULL);
      ares_free_query(query);
    }
  }

  /* See if the connections should be cleaned up */
  ares_check_cleanup_conns(channel);

  ares_queue_notify_empty(channel);
  ares_deferred_cb_leave(channel);
  ares_channel_unlock(channel);
}

ares_operation_t *ares_operation_create_nolock(ares_channel_t      *channel,
                                               ares_callback_dnsrec callback,
                                               void                *arg)
{
  ares_operation_t *operation = ares_malloc_zero(sizeof(*operation));
  if (operation == NULL) {
    return NULL;
  }
  operation->queries = ares_llist_create(NULL);
  if (operation->queries == NULL) {
    ares_free(operation);
    return NULL;
  }
#ifdef CARES_THREADS
  operation->lock = ares_thread_mutex_create();
  if (operation->lock == NULL) {
    ares_llist_destroy(operation->queries);
    ares_free(operation);
    return NULL;
  }
#endif
  operation->refs     = 2; /* caller and active callback */
  operation->channel  = channel;
  operation->callback = callback;
  operation->arg      = arg;
  return operation;
}

void ares_operation_retain(ares_operation_t *operation)
{
  if (operation == NULL) {
    return;
  }
  ares_thread_mutex_lock(operation->lock);
  operation->refs++;
  ares_thread_mutex_unlock(operation->lock);
}

void ares_operation_release(ares_operation_t *operation)
{
  ares_bool_t destroy;
  if (operation == NULL) {
    return;
  }
  ares_thread_mutex_lock(operation->lock);
  operation->refs--;
  destroy = operation->refs == 0 ? ARES_TRUE : ARES_FALSE;
  ares_thread_mutex_unlock(operation->lock);
  if (destroy) {
    ares_llist_destroy(operation->queries);
    ares_thread_mutex_destroy(operation->lock);
    ares_free(operation);
  }
}

void ares_operation_set_terminal_nolock(ares_operation_t *operation)
{
  ares_thread_mutex_lock(operation->lock);
  operation->terminal = ARES_TRUE;
  ares_thread_mutex_unlock(operation->lock);
}

void ares_operation_drain_nolock(ares_operation_t *operation,
                                 ares_status_t     status)
{
  ares_query_t *query;
  /* A last-child callback may release both active and caller references. */
  ares_operation_retain(operation);
  while ((query = ares_llist_first_val(operation->queries)) != NULL) {
    ares_detach_query(query);
    query->callback(query->arg, status, query->timeouts, NULL);
    ares_free_query(query);
  }
  ares_operation_release(operation);
}

void ares_operation_callback(void *arg, ares_status_t status, size_t timeouts,
                             const ares_dns_record_t *dnsrec)
{
  ares_operation_t    *operation = arg;
  ares_callback_dnsrec callback;
  void                *callback_arg;

  ares_thread_mutex_lock(operation->lock);
  operation->terminal = ARES_TRUE;
  callback            = operation->callback;
  callback_arg        = operation->arg;
  operation->callback = NULL;
  operation->arg      = NULL;
  operation->cancel_callback = NULL;
  operation->cancel_arg      = NULL;
  ares_thread_mutex_unlock(operation->lock);
  callback(callback_arg, status, timeouts, dnsrec);
  ares_operation_release(operation);
}

ares_status_t ares_operation_cancel(ares_channel_t   *channel,
                                    ares_operation_t *operation)
{
  ares_bool_t   terminal;

  if (operation == NULL) {
    return ARES_EFORMERR;
  }
  /* A terminal token is usable without accessing its former channel. Active
   * channel calls, including destroy, require the normal channel lifetime
   * synchronization from the caller. Never hold the token lock while taking
   * the channel lock: callbacks acquire them in the opposite order. */
  ares_thread_mutex_lock(operation->lock);
  terminal = operation->terminal;
  ares_thread_mutex_unlock(operation->lock);
  if (terminal) {
    return ARES_SUCCESS;
  }
  if (channel == NULL || operation->channel != channel) {
    return ARES_EFORMERR;
  }
  ares_channel_lock(channel);
  ares_deferred_cb_enter(channel);
  ares_thread_mutex_lock(operation->lock);
  terminal = operation->terminal;
  ares_thread_mutex_unlock(operation->lock);
  if (!terminal) {
    ares_operation_set_terminal_nolock(operation);
    if (operation->cancel_callback != NULL) {
      operation->cancel_callback(operation->cancel_arg, ARES_ECANCELLED);
    } else {
      ares_operation_drain_nolock(operation, ARES_ECANCELLED);
    }
  }
  ares_check_cleanup_conns(channel);
  ares_queue_notify_empty(channel);
  ares_deferred_cb_leave(channel);
  ares_channel_unlock(channel);
  return ARES_SUCCESS;
}
