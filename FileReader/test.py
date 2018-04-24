import tensorflow as tf

filename_queue = tf.train.string_input_producer(["test.csv"])
print(filename_queue)
reader = tf.TextLineReader()
key, value = reader.read(filename_queue)
print(key, value)
record_defaults = [[''], [''], ['']]
col1, col2, col3 = tf.decode_csv(value, record_defaults=record_defaults)
print(col1, col2, col3)
# features = tf.concat([col1, col2, col3], axis=0)

with tf.Session() as sess:
    sess.run(key)
    print(key)
    # Start populating the filename queue.
    coord = tf.train.Coordinator()
    threads = tf.train.start_queue_runners(coord=coord)

    for i in range(1200):
        # Retrieve a single instance:
        example1, example2, example3 = sess.run([col1, col2, col3])
        example1 = example1.decode('utf8')
        example2 = example2.decode('utf8')
        example3 = example3.decode('utf8')
        print(example1, example2, example3)

    coord.request_stop()
    coord.join(threads)
