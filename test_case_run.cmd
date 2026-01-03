## How to Run Tests

### Run All Tests with Coverage
```powershell
mvn clean test
```

### View HTML Coverage Report
```powershell
# Report is generated at:
target/site/jacoco/index.html
```

### Run Specific Test Class
```powershell
mvn test -Dtest=ConfigTest
```

### Run Tests with Output
```powershell
mvn clean test -X
```