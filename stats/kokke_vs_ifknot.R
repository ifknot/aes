library(ggplot2)
library(dplyr)

kokke.encrypt = data.frame(AES = "kokke", value = select(kokke_HPZ600, encrypt))
ifknot.encrypt = data.frame(AES = "ifknot", value = select(ifknot_HPZ600, encrypt))
plot1.data = rbind(kokke.encrypt, ifknot.encrypt)
#ggplot(plot.data, aes(x=group, y=encrypt, fill=group)) + geom_boxplot() +
hpz600.encrypt <- ggplot(plot1.data, aes(x=AES, y=encrypt, fill=AES)) + geom_violin() +
  scale_y_continuous("time (seconds)") +
  ggtitle("Violin Plot: 50 trials of execution time 1,000,000 ECB encrypts HP Z600") +
  scale_fill_brewer(palette="Set1")

kokke.decrypt = data.frame(AES = "kokke", value = select(kokke_HPZ600, decrypt))
ifknot.decrypt = data.frame(AES = "ifknot", value = select(ifknot_HPZ600, decrypt))
plot2.data = rbind(kokke.decrypt, ifknot.decrypt)
#ggplot(plot.data, aes(x=group, y=encrypt, fill=group)) + geom_boxplot() +
hpz600.decrypt <- ggplot(plot2.data, aes(x=AES, y=decrypt, fill=AES)) + geom_violin() +
  scale_y_continuous("time (seconds)") +
  ggtitle("Violin Plot: 50 trials of execution time 1,000,000 ECB decrypts HP Z600") +
  scale_fill_brewer(palette="Set2")

kokke.encrypt = data.frame(AES = "kokke", value = select(kokke_P52, encrypt))
ifknot.encrypt = data.frame(AES = "ifknot", value = select(ifknot_P52, encrypt))
plot1.data = rbind(kokke.encrypt, ifknot.encrypt)
#ggplot(plot.data, aes(x=group, y=encrypt, fill=group)) + geom_boxplot() +
p52.encrypt <- ggplot(plot1.data, aes(x=AES, y=encrypt, fill=AES)) + geom_violin() +
  scale_y_continuous("time (seconds)") +
  ggtitle("Violin Plot: 50 trials of execution time 1,000,000 ECB encrypts Lenovo P52") +
  scale_fill_brewer(palette="Set3")

kokke.decrypt = data.frame(AES = "kokke", value = select(kokke_P52, decrypt))
ifknot.decrypt = data.frame(AES = "ifknot", value = select(ifknot_P52, decrypt))
plot2.data = rbind(kokke.decrypt, ifknot.decrypt)
#ggplot(plot.data, aes(x=group, y=encrypt, fill=group)) + geom_boxplot() +
p52.decrypt <- ggplot(plot2.data, aes(x=AES, y=decrypt, fill=AES)) + geom_violin() +
  scale_y_continuous("time (seconds)") +
  ggtitle("Violin Plot: 50 trials of execution time 1,000,000 ECB decrypts Lenovo P52") +
  scale_fill_brewer(palette="Dark2")