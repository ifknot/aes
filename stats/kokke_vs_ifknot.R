library(ggplot2)
library(dplyr)

kokke.encrypt = data.frame(AES = "kokke", value = select(kokke_HPZ600, encrypt))
ifknot.encrypt = data.frame(AES = "ifknot", value = select(ifknot_HPZ600, encrypt))
plot1.data = rbind(kokke.encrypt, ifknot.encrypt)
#ggplot(plot.data, aes(x=group, y=encrypt, fill=group)) + geom_boxplot() +
vs.encrypt <- ggplot(plot1.data, aes(x=AES, y=encrypt, fill=AES)) + geom_violin() +
    scale_y_continuous("time (seconds)") +
    ggtitle("Violin Plot: 50 trials of execution time 1,000,000 ECB encrypts")

kokke.decrypt = data.frame(AES = "kokke", value = select(kokke_HPZ600, encrypt))
ifknot.decrypt = data.frame(AES = "ifknot", value = select(ifknot_HPZ600, encrypt))
plot2.data = rbind(kokke.decrypt, ifknot.decrypt)
#ggplot(plot.data, aes(x=group, y=encrypt, fill=group)) + geom_boxplot() +
vs.decrypt <- ggplot(plot2.data, aes(x=AES, y=encrypt, fill=AES)) + geom_violin() +
    scale_y_continuous("time (seconds)") +
    ggtitle("Violin Plot: 50 trials of execution time 1,000,000 ECB decrypts")


