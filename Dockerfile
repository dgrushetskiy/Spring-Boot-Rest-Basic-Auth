FROM adoptopenjdk/openjdk15:ubi
COPY target/*.jar app.jar
Expose 8080
# Run the Jar
CMD ["java", "-jar", "app.jar"]
