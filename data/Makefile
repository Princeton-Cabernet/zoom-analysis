
BIN_PATH=../build
DATASET_NAME=zoom-5min

all: stats.html streams.html meetings.html frames.html

$(DATASET_NAME).zpkt flows.csv rate.csv types.csv: $(DATASET_NAME).pcap
	${BIN_PATH}/zoom_flows -i $< -f flows.csv -t types.csv -r rate.csv -z $@

pkts.csv streams.csv frames.csv stats.csv: $(DATASET_NAME).zpkt
	${BIN_PATH}/zoom_rtp -i $< -p pkts.csv -s streams.csv -f frames.csv -t stats.csv

meetings.csv unique.csv: $(DATASET_NAME).zpkt
	${BIN_PATH}/zoom_meetings -i $< -m meetings.csv -u unique.csv

%.html: %.Rmd %.csv setup.R
	Rscript -e 'library(rmarkdown); rmarkdown::render("$<")'

clean:
	$(RM) -r fig *.html

spotless: clean
	$(RM) *.csv *.zpkt

.PHONY: all clean spotless
