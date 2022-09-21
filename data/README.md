# Example Dataset and Data Analysis Scripts

## Dataset

* The example dataset contains 5 minutes of Zoom media packets being sent from a Zoom client
  * 2 media streams (1 audio, 1 video), 40,749 Zoom media packets
  * Use the R markdown notebooks as inspiration of the types of analyses possible
  * The examples included are by no means exhaustive and many are not particularly interesting
    or revealing when used on such a small dataset

## Generate Plots and Reports

* If you compiled the analysis programs to the /build directory, use the Makefile in this directory
  to generate a series of plots and reports. A subset of these plots have been used (although for
  a much larger dataset) in our paper.

* To generate all *.csv* data files and *stats.html, streams.html,* and *meetings.html*:
```
make all  
```

## Prerequisites

* To generate the R markdown notebooks, please install R together with the following packages:
  * dplyr
  * ggplot2
  * knitr
  * lubridate
  * purrr
  * readr
  * magrittr
  * scales
  * tibble
  * tidyr