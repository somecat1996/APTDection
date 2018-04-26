import tensorflow as tf
from .NeutralNetwork import *


tf.logging.set_verbosity(tf.logging.INFO)
DataPath = "../DataPath/"
TrainRate = 0.8
ModelPath = "../ModelPath/"

def main(unused):
    packets_train, labels_train, packets_eval, labels_eval = ReadData(DataPath, TrainRate)
    classifier = tf.estimator.Estimator(
        model_fn=NeutralNetwork,
        model_dir=ModelPath)

    tensors_to_log = {"probabilities": "softmax_tensor"}
    logging_hook = tf.train.LoggingTensorHook(
        tensors=tensors_to_log,
        every_n_iter=50)

    train_input_fn = tf.estimator.inputs.numpy_input_fn(
        x={"packet": packets_train},
        y=labels_train,
        batch_size=100,
        num_epochs=None,
        shuffle=True)
    classifier.train(
        input_fn=train_input_fn,
        steps=20000,
        hooks=[logging_hook])

    eval_input_fn = tf.estimator.inputs.numpy_input_fn(
        x={"packet": packets_eval},
        y=labels_eval,
        num_epochs=1,
        shuffle=False)
    eval_results = classifier.evaluate(input_fn=eval_input_fn)
    print(eval_results)

if __name__ == "__main__":
    tf.app.run()
