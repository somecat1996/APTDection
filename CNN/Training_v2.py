from .NeutralNetwork import *
from .InputData import *

DataPath = "./DataPath/"
TrainRate = 0.8
ModelPath = "./ModelPath/"

packets_train, labels_train, packets_eval, labels_eval = ReadData(DataPath, TrainRate)
packets = tf.placeholder(tf.float32, shape=[-1, 28 * 28], name='packets')
labels = tf.placeholder(tf.float32, shape=[-1], name='labels')

regularizer = tf.contrib.layers.l2_regularizer(0.0001)
