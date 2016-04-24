## Useful maven commands:

```sh
mvn -U versions:display-dependency-updates versions:display-plugin-updates
mvn dependency:resolve -Dclassifier=sources
mvn dependency:resolve -Dclassifier=javadoc
mvn deploy site-deploy
mvn source:jar source:test-jar javadoc:javadoc javadoc:test-javadoc
mvn --encrypt-master-password <password>
mvn --encrypt-password <password>
mvn release:prepare release:perform
```
