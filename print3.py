from numpy import *

# p = [(0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.9375, 0.0625), (0.0, 1.0), (0.5, 0.5), (0.0, 1.0), (0.0, 1.0), (0.6666666666666667, 0.3333333333333333), (0.33333333333333337, 0.6666666666666666), (0.0, 1.0), (0.5, 0.5), (0.0, 1.0)]
# print(len(p))
# l = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
p = [(0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.5, 0.5), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.9375, 0.0625), (0.0, 1.0), (0.5, 0.5), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.6666666666666667, 0.3333333333333333), (0.0, 1.0), (0.33333333333333337, 0.6666666666666666), (0.0, 1.0), (0.0, 1.0), (0.5, 0.5), (0.0, 1.0), (0.0, 1.0)]
print(len(p))
l = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

def plotROC(predStrengths, classLabels):
    import matplotlib.pyplot as plt
    cur = [1.0, 1.0]
    ySum = 0.0
    numPosClas = sum(array(classLabels) == 1.0)
    yStep = 1 / float(numPosClas)
    xStep = 1 / float(len(classLabels) - numPosClas)
    sortedIndicies = predStrengths.argsort()
    fig = plt.figure()
    fig.clf()
    ax = plt.subplot(111)
    for index in sortedIndicies.tolist()[0]:
        # print(sortedIndicies.tolist())
        if classLabels[index] == 1.0:
            delX = 0
            delY = yStep
        else:
            delX = xStep
            delY = 0
            ySum += cur[1]
        ax.plot([cur[0], cur[0] - delX], [cur[1], cur[1] - delY], c='b')
        cur = (cur[0] - delX, cur[1] - delY)
    ax.plot([0, 1], [0, 1], 'b--')
    plt.xlabel("False Positive Rate")
    plt.ylabel('True Positive Rate')
    plt.title('ROC curve for System')
    ax.axis([0, 1, 0, 1])
    plt.show()
    print("the area under the curve is:", ySum * xStep)


plotROC(mat(p), l)
