FROM --platform=linux/amd64 maven:3.9-eclipse-temurin-21
WORKDIR /workspace
RUN apt-get update && apt-get install -y unzip curl bash
RUN curl -Ls https://sh.jbang.dev | bash -s - trust add https://repo1.maven.org/maven2/io/quarkus/quarkus-cli/
RUN curl -Ls https://sh.jbang.dev | bash -s - app install --fresh --force quarkus@quarkusio
EXPOSE 8080