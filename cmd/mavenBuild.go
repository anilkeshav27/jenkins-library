package cmd

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/SAP/jenkins-library/pkg/command"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/maven"
	"github.com/SAP/jenkins-library/pkg/telemetry"
	"github.com/pkg/errors"

	piperhttp "github.com/SAP/jenkins-library/pkg/http"
)

func mavenBuild(config mavenBuildOptions, telemetryData *telemetry.CustomData) {

	utils := maven.NewUtilsBundle()

	err := runMavenBuild(&config, telemetryData, utils)
	if err != nil {
		log.Entry().WithError(err).Fatal("step execution failed")
	}
}

func runMavenBuild(config *mavenBuildOptions, telemetryData *telemetry.CustomData, utils maven.Utils) error {
	downloadClient := &piperhttp.Client{}

	deployFlags := []string{"-Dmaven.install.skip=true", "-Dmaven.wagon.http.ssl.insecure=true"}

	position, found := Find(config.Flags, "DaltDeploymentRepository=internal")

	if found {
		deployFlags = append(deployFlags, config.Flags[position])

		// removing alt deployment repository since that is not needed during install / verify phases
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
			runner := &command.Command{}
			if err := loadRemoteRepoCertificates(config.CustomTLSCertificateLinks, downloadClient, &deployFlags, runner); err != nil {
				log.SetErrorCategory(log.ErrorInfrastructure)
				return err
			}
			/* loadRemoteRepoCertificates() */
			mavenOptions.Flags = deployFlags
			mavenOptions.Goals = []string{"deploy"}
			mavenOptions.Defines = []string{}
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

func loadRemoteRepoCertificates(certificateList []string, client piperhttp.Downloader, flags *[]string, runner command.ExecRunner) error {
	trustStoreFile := filepath.Join(getWorkingDir(), "/maven/ssl/certs/", "ca-certificates.crt")

	if exists, _ := fileUtilsExists(trustStoreFile); exists {
		// use local existing trust store
		/* sonar.addEnvironment("SONAR_SCANNER_OPTS=-Djavax.net.ssl.trustStore=" + trustStoreFile + " -Djavax.net.ssl.trustStorePassword=changeit") */
		*flags = append(*flags, "-Djavax.net.ssl.trustStore="+trustStoreFile, " -Djavax.net.ssl.trustStorePassword=changeit")
		log.Entry().WithField("trust store", trustStoreFile).Info("Using local trust store")
	} else
	//TODO: certificate loading is deactivated due to the missing JAVA keytool
	// see https://github.com/SAP/jenkins-library/issues/1072
	if len(certificateList) > 0 {
		// use local created trust store with downloaded certificates
		keytoolOptions := []string{
			"-import",
			"-noprompt",
			"-storepass", "changeit",
			"-keystore", trustStoreFile,
		}
		tmpFolder := getTempDir()
		defer os.RemoveAll(tmpFolder) // clean up

		for _, certificate := range certificateList {
			filename := path.Base(certificate) // decode?
			target := filepath.Join(tmpFolder, filename)

			log.Entry().WithField("source", certificate).WithField("target", target).Info("Downloading TLS certificate")
			// download certificate
			if err := client.DownloadFile(certificate, target, nil, nil); err != nil {
				return errors.Wrapf(err, "Download of TLS certificate failed")
			}
			options := append(keytoolOptions, "-file", target)
			options = append(options, "-alias", filename)
			// add certificate to keystore
			if err := runner.RunExecutable("keytool", options...); err != nil {
				return errors.Wrap(err, "Adding certificate to keystore failed")
			}
		}
		*flags = append(*flags, "-Djavax.net.ssl.trustStore="+trustStoreFile, " -Djavax.net.ssl.trustStorePassword=changeit")
		log.Entry().WithField("trust store", trustStoreFile).Info("Using local trust store")
	} else {
		log.Entry().Debug("Download of TLS certificates skipped")
	}
	return nil
}
