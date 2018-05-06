import tensorflow as tf
import os
import numpy as np


def ReadData(path, trainrate=0.8):
    files = [x for x in os.listdir(path)]
    packets = []
    labels = []
    for file in files:
        packet = []
        payload = open(path+file, 'rb').read()
        if len(payload) < 1024:
            payload += (1024 - len(payload)) * b'\x00'
        for i in payload:
            packet.append(i)
        packets.append(packet)
        labels.append(int(file[-1]))
    packets = np.asarray(packets, np.float32)
    labels = np.asarray(labels, np.int32)
    shuffle = np.arange(len(packets))
    np.random.shuffle(shuffle)
    packets = packets[shuffle]
    labels = labels[shuffle]

    s = np.int(len(packets) * trainrate)
    packets_train = packets[:s]
    labels_train = labels[:s]
    packets_eval = packets[s:]
    labels_eval = labels[s:]

    # packets_train = tf.cast(packets_train, tf.string)
    # labels_train = tf.cast(labels_train, tf.int32)
    # packets_eval = tf.cast(packets_eval, tf.string)
    # labels_eval = tf.cast(labels_eval, tf.int32)

    return packets_train, labels_train, packets_eval, labels_eval


# 输入为[批大小，宽度，高度，深度]
# -1代表自动处理当前大小
INPUTSHAPE = [-1, 32, 32, 1]  # 输入形状

# 第一层卷积层输入形状为[批大小，32，32，1]
# 第一层卷积层输出形状为[批大小，32，32，32]
FILTER1_NUM = 32  # 第一层滤波器数量
FILTER1_SHAPE = [5, 5]  # 第一层滤波器形状

# 第一层池化层输入形状为[批大小，32，32，32]
# 第一层池化层输出形状为[批大小，16，16，32]
POOL1_SHAPE = [2, 2]  # 第一层池化层形状
POOL1_STRIDE = 2  # 第一层池化层步长

# 第二层卷积层输入形状为[批大小，16，16，32]
# 第二层卷积层输出形状为[批大小，16，16，64]
FILTER2_NUM = 64  # 第二层滤波器数量
FILTER2_SHAPE = [5, 5]  # 第二层滤波器形状

# 第二层池化层输入形状为[批大小，16，16，64]
# 第二层池化层输出形状为[批大小，8，8，64]
POOL2_SHAPE = [2, 2]  # 第二层池化层形状
POOL2_STRIDE = 2  # 第二层池化层步长

# 展平前输入形状为[批大小，8，8，64]
# 展平后形状为[批大小，8*8*64]
FLAT_SHAPE = [-1, 8 * 8 * 64]  # 展平后形状

# 全连接层输入形状为[批大小，7*7*64]
# 全连接层输出个数为[批大小，1024]
DENSE_UNIT = 1024  # 全连接层输出个数

# 按概率丢弃神经元，避免过拟合
DROPOUT_RATE = 0.4  # 丢弃概率

# 输出个数，代表分类结果
OUTPUT_UNIT = 2

# 学习率
LEARNING_RATE = 0.001


def NeutralNetwork(features, labels, mode):
    # 重置输入形状
    print(features["packet"])
    input_layer = tf.reshape(features["packet"], INPUTSHAPE)

    # 第一层卷积层，创建FILTER1_NUM个形状为FILTER1_SHAPE的滤波器
    # 采用默认步长(1, 1)，卷积结果填充为与输入相同大小
    # 使用激活函数max(feature, 0)
    conv1 = tf.layers.conv2d(
        inputs=input_layer,
        filters=FILTER1_NUM,
        kernel_size=FILTER1_SHAPE,
        padding="same",
        activation=tf.nn.relu)

    # 第一层池化层，采用形状为POOL1_SHAPE，步长为POOL1_STRIDE
    pool1 = tf.layers.max_pooling2d(
        inputs=conv1,
        pool_size=POOL1_SHAPE,
        strides=POOL1_STRIDE)

    # 第一层卷积层，创建FILTER2_NUM个形状为FILTER2_SHAPE的滤波器
    # 采用默认步长(1, 1)，卷积结果填充为与输入相同大小
    # 使用激活函数max(feature, 0)
    conv2 = tf.layers.conv2d(
        inputs=pool1,
        filters=FILTER2_NUM,
        kernel_size=FILTER2_SHAPE,
        padding="same",
        activation=tf.nn.relu)

    # 第一层池化层，采用形状为POOL2_SHAPE，步长为POOL2_STRIDE
    pool2 = tf.layers.max_pooling2d(
        inputs=conv2,
        pool_size=POOL2_SHAPE,
        strides=POOL2_STRIDE)

    # 展平输出为[批大小, FLAT_SHAPE]
    pool2_flat = tf.reshape(
        tensor=pool2,
        shape=FLAT_SHAPE)

    # 全连接层，输出为[批大小, DENSE_UNIT]
    # 使用激活函数max(feature, 0)
    dense = tf.layers.dense(
        inputs=pool2_flat,
        units=DENSE_UNIT,
        activation=tf.nn.relu)

    # 按DROPOUT_RATE随机丢弃神经元
    dropout = tf.layers.dropout(
        inputs=dense,
        rate=DROPOUT_RATE,
        training=mode == tf.estimator.ModeKeys.TRAIN)

    # 逻辑回归层，最终获得OUTPUT_UNIT个输出
    logits = tf.layers.dense(
        inputs=dropout,
        units=OUTPUT_UNIT)

    # 预测
    predictions = {
        # argmax返回第axis的索引所对应的最大值的索引
        # logits形状为[批大小, 2]，则其返回每一批中
        # 最大值的索引——0或1
        "classes": tf.argmax(input=logits, axis=1),
        # 默认对最后一个维度计算softmax函数
        "probabilities": tf.nn.softmax(logits, name="softmax_tensor")}

    # 如果目前是预测状态，返回预测结果
    if mode == tf.estimator.ModeKeys.PREDICT:
        return tf.estimator.EstimatorSpec(mode=mode, predictions=predictions)

    # 目前不是预测状态，获得损失函数
    loss = tf.losses.sparse_softmax_cross_entropy(labels=labels, logits=logits)

    # 配置训练操作
    if mode == tf.estimator.ModeKeys.TRAIN:
        optimizer = tf.train.GradientDescentOptimizer(learning_rate=LEARNING_RATE)
        train_op = optimizer.minimize(
            loss=loss,
            global_step=tf.train.get_global_step())
        return tf.estimator.EstimatorSpec(mode=mode, loss=loss, train_op=train_op)

    # 添加评价指标
    eval_metric_ops = {
            "accuracy": tf.metrics.accuracy(
                labels=labels,
                predictions=predictions["classes"])}
    return tf.estimator.EstimatorSpec(
        mode=mode,
        loss=loss,
        eval_metric_ops=eval_metric_ops)


tf.logging.set_verbosity(tf.logging.INFO)
DataPath = "./DataPath/"
TrainRate = 0.8
ModelPath = "./ModelPath2/"

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
