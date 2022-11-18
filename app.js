const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dbPath = path.join(__dirname, "covid19IndiaPortal.db");

const app = express();
app.use(express.json());
let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server is Running at http://localhost:3000");
    });
  } catch (e) {
    console.log(e.message);
    process.exit(1);
  }
};

initializeDBAndServer();

//REGISTER USER API
app.post("/register/", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const passwordLength = password.length;
  const getUserQuery = `
    SELECT 
        * 
    FROM 
        user 
    WHERE 
        username = "${username}"
  `;

  const dbUser = await db.get(getUserQuery);

  if (dbUser === undefined) {
    if (passwordLength < 5) {
      response.status(400);
      response.send("Password is too short");
    } else {
      const createUserQuery = `
            INSERT INTO 
                user (username, name, password, gender, location)
            VALUES (
                "${username}",
                "${name}",
                "${hashedPassword}",
                "${gender}",
                "${location}"
            )
        `;
      await db.run(createUserQuery);
      response.status(200);
      response.send("User created successfully");
    }
  } else {
    response.status(400);
    response.send("User already exists");
  }
});

//ADD USER LOGIN API
app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  const getUserQuery = `
        SELECT
            *
        FROM    
            user
        WHERE
            username = "${username}"
    `;
  const dbUser = await db.get(getUserQuery);

  if (dbUser !== undefined) {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched === true) {
      const payload = { username: username };
      const jwtToken = jwt.sign(payload, "THE_SECRET_TOKEN");
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  } else {
    response.status(400);
    response.send("Invalid user");
  }
});
//ADD authenticateToken middlewareFunction
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers["authorization"];
  let jwtToken;
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "THE_SECRET_TOKEN", (error, user) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        next();
      }
    });
  }
};

//ADD GET States API
app.get("/states/", authenticateToken, async (request, response) => {
  const getStatesQuery = `
        SELECT
            * 
        FROM 
            state`;
  const newState = (statesObj) => {
    return {
      stateId: statesObj.state_id,
      stateName: statesObj.state_name,
      population: statesObj.population,
    };
  };
  let stateArray = [];
  const statesArray = await db.all(getStatesQuery);
  for (let state of statesArray) {
    stateArray.push(newState(state));
  }
  response.send(stateArray);
});

//ADD GET State API
app.get("/states/:stateId", authenticateToken, async (request, response) => {
  const { stateId } = request.params;
  const getStateQuery = `
        SELECT 
            * 
        FROM 
            state
        WHERE 
            state_id = ${stateId}
    `;
  const newState = (statesObj) => {
    return {
      stateId: statesObj.state_id,
      stateName: statesObj.state_name,
      population: statesObj.population,
    };
  };
  const stateObj = await db.get(getStateQuery);
  const state = newState(stateObj);
  response.send(state);
});

//ADD CREATE DISTRICT API
app.post("/districts/", authenticateToken, async (request, response) => {
  const { districtName, stateId, cases, cured, active, deaths } = request.body;
  const createDistrictQuery = `
        INSERT  INTO 
            district (district_name, state_id, cases, cured, active, deaths) 
        VALUES (
            "${districtName}",
            "${stateId}",
            "${cases}",
            "${cured}",
            "${active}",
            "${deaths}"
        )
  `;
  await db.run(createDistrictQuery);
  response.send("District Successfully Added");
});

//ADD GET District API
app.get(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const getDistrictQuery = `
        SELECT
            * 
        FROM 
            district
        WHERE
            district_id = ${districtId}
    `;
    const convertResponseObjToDistrictObj = (districtObj) => {
      return {
        districtId: districtObj.district_id,
        districtName: districtObj.district_name,
        stateId: districtObj.state_id,
        cases: districtObj.cases,
        cured: districtObj.cured,
        active: districtObj.active,
        deaths: districtObj.deaths,
      };
    };
    const districtObj = await db.get(getDistrictQuery);
    const result = convertResponseObjToDistrictObj(districtObj);
    response.send(result);
  }
);
//ADD DELETE District API
app.delete(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const deleteDistrictQuery = `
        DELETE FROM 
            district 
        WHERE
            district_id = ${districtId}
    `;

    await db.run(deleteDistrictQuery);
    response.send("District Removed");
  }
);

//UPDATE district API
app.put(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const {
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
    } = request.body;
    const updateDistrictQuery = `
        UPDATE 
            district
        SET  
            district_name = "${districtName}",
            state_id = "${stateId}",
            cases = "${cases}",
            cured = "${cured}",
            active = "${active}",
            deaths = "${deaths}"
        WHERE
            district_id = ${districtId}
    `;
    await db.run(updateDistrictQuery);
    response.send("District Details Updated");
  }
);

//GET State Stats API
app.get(
  "/states/:stateId/stats/",
  authenticateToken,
  async (request, response) => {
    const { stateId } = request.params;
    const getStateStatsQuery = `
        SELECT
            SUM(cases) AS totalCases,
            SUM(cured) AS totalCured,
            SUM(active) AS totalActive,
            SUM(deaths) AS totalDeaths
        FROM
            state NATURAL JOIN district 
        WHERE
            state_id  = ${stateId}

    `;
    const result = await db.get(getStateStatsQuery);
    response.send(result);
  }
);

module.exports = app;
