#install.packages("ggplot2",dependencies=TRUE)
library(ggplot2)
kokke.HPZ600 <- read.csv("kokke_HPZ600.csv")
ggplot(kokke.HPZ600, aes(x = "",y = "encrypt") + geom_violin() )
