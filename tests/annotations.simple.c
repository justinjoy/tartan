#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <gio/gio.h>

/*
 * No error
 */
void
g_input_stream_read_async (GInputStream *stream,
                           void *buffer,
                           gsize count,
                           int io_priority,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	// Do nothing.
}
