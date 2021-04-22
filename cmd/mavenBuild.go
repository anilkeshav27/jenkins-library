package cmd

import (
	"strings"

	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/maven"
	"github.com/SAP/jenkins-library/pkg/telemetry"
)

func mavenBuild(config mavenBuildOptions, telemetryData *telemetry.CustomData) {

	utils := maven.NewUtilsBundle()

	err := runMavenBuild(&config, telemetryData, utils)
	if err != nil {
		log.Entry().WithError(err).Fatal("step execution failed")
	}
}

func runMavenBuild(config *mavenBuildOptions, telemetryData *telemetry.CustomData, utils maven.Utils) error {
	log.Entry().Infof("found flags %v", config.Flags)
	deployFlags := []string{"-Dmaven.install.skip=true"}

	position, found := Find(config.Flags, "DaltDeploymentRepository=internal")

	if found {
		deployFlags = append(deployFlags, config.Flags[position])

		config.Flags[position] = config.Flags[len(config.Flags)-1] // Copy last element to index i.
		config.Flags[len(config.Flags)-1] = ""                     // Erase last element (write zero value).
		config.Flags = config.Flags[:len(config.Flags)-1]          // Truncate slice.
	}

	var flags = []string{"-update-snapshots", "--batch-mode"}

	exists, _ := utils.FileExists("integration-tests/pom.xml")
	if exists {
		flags = append(flags, "-pl", "!integration-tests")
	}

	if config.Flags != nil {
		flags = append(flags, config.Flags...)
	}

	var defines []string
	var goals []string

	goals = append(goals, "org.jacoco:jacoco-maven-plugin:prepare-agent")

	if config.Flatten {
		goals = append(goals, "flatten:flatten")
		defines = append(defines, "-Dflatten.mode=resolveCiFriendliesOnly", "-DupdatePomFile=true")
	}

	if config.CreateBOM {
		goals = append(goals, "org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom")
		createBOMConfig := []string{
			"-DschemaVersion=1.2",
			"-DincludeBomSerialNumber=true",
			"-DincludeCompileScope=true",
			"-DincludeProvidedScope=true",
			"-DincludeRuntimeScope=true",
			"-DincludeSystemScope=true",
			"-DincludeTestScope=false",
			"-DincludeLicenseText=false",
			"-DoutputFormat=xml",
		}
		defines = append(defines, createBOMConfig...)
	}

	if config.Verify {
		goals = append(goals, "verify")
	} else {
		goals = append(goals, "install")
	}

	mavenOptions := maven.ExecuteOptions{
		Flags:                       flags,
		Goals:                       goals,
		Defines:                     defines,
		PomPath:                     config.PomPath,
		ProjectSettingsFile:         config.ProjectSettingsFile,
		GlobalSettingsFile:          config.GlobalSettingsFile,
		M2Path:                      config.M2Path,
		LogSuccessfulMavenTransfers: config.LogSuccessfulMavenTransfers,
	}

	_, err := maven.Execute(&mavenOptions, utils)
	//return err
	if err == nil {
		if config.Publish && !config.Verify {
			log.Entry().Infof("publish detected, running mvn deploy")
			mavenOptions.Flags = deployFlags
			mavenOptions.Goals = []string{"deploy"}
			mavenOptions.Defines = []string{}
			/* mavenDeployOption := maven.ExecuteOptions{
				Flags:                       deployFlags,
				Goals:                       []string{"deploy"},
				Defines:                     []string{},
				PomPath:                     config.PomPath,
				ProjectSettingsFile:         config.ProjectSettingsFile,
				GlobalSettingsFile:          config.GlobalSettingsFile,
				M2Path:                      config.M2Path,
				LogSuccessfulMavenTransfers: config.LogSuccessfulMavenTransfers,
			} */
			_, err := maven.Execute(&mavenOptions, utils)
			return err
		} else {
			log.Entry().Infof("publish not detected, ignoring maven deploy")
		}
	}

	return err
}
func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if strings.Contains(item, val) {
			return i, true
		}
	}
	return -1, false
}
