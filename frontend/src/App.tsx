import { Button, Container, Grid, TextField, ThemeProvider, Typography, Stack, Tooltip, createTheme, styled, Box, Snackbar, Alert, Slide, RadioGroup, Radio, InputAdornment, FormControlLabel, FormControl, FormLabel, CircularProgress } from '@mui/material';
import React, { useEffect } from 'react';
import './App.css';
import { deepOrange, lightBlue, orange, red, yellow } from '@mui/material/colors';
import { GoogleReCaptchaProvider, IGoogleReCaptchaConsumerProps, useGoogleReCaptcha } from 'react-google-recaptcha-v3';

interface IInputFileProps {
  files: File[],
}

interface WasmProps {
  wasm: WasmType,
}

const theme = createTheme({
  palette: {
    primary: {
      main: deepOrange[500],
    },
    secondary: {
      main: orange[200],
    },
    error: {
      main: red[700],
    },
    warning: {
      main: yellow[400],
    },
    info: {
      main: lightBlue[400],
    }
  },
});

const Input = styled('input')({
  display: 'none',
});

const WrappedButton: React.FC<IInputFileProps & React.ComponentProps<typeof Button>> = ({ files, children, ...props }) => {
  if (files.length === 0) {
    return (<Tooltip title={<div className="tooltip-text">레지스트리 파일을 선택하세요</div>} followCursor>
      <span>
        <Button {...props} disabled>
          <>{children}</>
        </Button>
      </span>
    </Tooltip>);
  }

  return (
    <Button {...props}>
      <>{children}</>
    </Button>
  );
}

const Title: React.FC = () => (
  <Container className="app-title">
    <Typography variant="h2">메이플스토리 설정 연동<div className="beta-sup"><i>beta</i></div></Typography>
  </Container>
);

const UploadForm: React.FC<IGoogleReCaptchaConsumerProps & WasmProps> = ({ executeRecaptcha, wasm }) => {
  interface IFormValidation {
    name: string | undefined,
    password: string | undefined,
  };

  const [files, setFiles] = React.useState<File[]>([]);
  const [validation, setValidation] = React.useState<IFormValidation>({ name: undefined, password: undefined });
  const [inProgress, setInProgress] = React.useState<boolean>(false);
  const nameRef = React.useRef<HTMLInputElement>(null);
  const passwordRef = React.useRef<HTMLInputElement>(null);
  const passwordCheckRef = React.useRef<HTMLInputElement>(null);
  const [alertComponent, setAlertComponent] = React.useState<React.ReactElement | undefined>(undefined);

  const onClick = React.useCallback(async () => {
    if (executeRecaptcha === undefined) {
      return;
    }

    if (!inProgress) {
      setInProgress(true);
    }
  }, [executeRecaptcha, inProgress]);

  useEffect(() => {
    if (!inProgress || executeRecaptcha === undefined) {
      return;
    }

    (async () => {
      const v: IFormValidation = {
        name: undefined,
        password: undefined
      };

      try {
        try {
          if ((nameRef.current?.value.length || 0) < 3) {
            v.name = "3글자 이상이어야 합니다.";
          }

          if ((passwordRef.current?.value || "") !== (passwordCheckRef.current?.value || "")) {
            v.password = "두 비밀번호가 다릅니다.";
            return;
          }

          if ((passwordRef.current?.value.length || 0) < 6) {
            v.password = "비밀번호는 6글자 이상이어야 합니다."
          }
        } finally {
          setValidation(v);
        }

        if (!!v.name || !!v.password) {
          return;
        }

        const token = await executeRecaptcha();
        const buffer = await files[0].arrayBuffer();
        try {
          await wasm.store_put(new Uint8Array(buffer), nameRef.current!!.value, passwordRef.current!!.value, token);
          const successAlert = (<Alert onClose={() => setAlertComponent(undefined)} severity="success" sx={{ width: "100%" }}>
            업로드에 성공하였습니다
          </Alert>);
          setAlertComponent(successAlert);
        } catch (e: any) {
          const errorAlert = (<Alert onClose={() => setAlertComponent(undefined)} severity="error" sx={{ width: "100%" }}>
            {`업로드에 실패했습니다: ${String(e)}`}
          </Alert>);
          setAlertComponent(errorAlert);
        }
      } finally {
        setInProgress(false);
      }
    })();
  }, [executeRecaptcha, wasm, files, inProgress]);

  const onFileChange = React.useCallback((ev: React.ChangeEvent<HTMLInputElement>) => {
    const f = ev.target.files;
    if (f === null) {
      return;
    }

    setFiles([f[0]]);
  }, []);

  return (
    <Stack className="id-pw-input" spacing={2} width="md">
      <Typography variant="h5">설정 업로드</Typography>
      <TextField label="이름" variant="filled" error={!!validation.name} helperText={validation.name} inputRef={nameRef}></TextField>
      <TextField label="비밀번호" variant="outlined" type="password" error={!!validation.password} helperText={validation.password} inputRef={passwordRef}></TextField>
      <TextField label="비밀번호(확인)" variant="outlined" type="password" error={!!validation.password} helperText={validation.password} inputRef={passwordCheckRef}></TextField>
      <Grid container justifyContent="space-between" width="md">
        {inProgress ? <>
          <CircularProgress />
          <Box component="span" style={{ "marginLeft": "0.8em" }} />
        </>
          : <></>}
        <label htmlFor="file-selector-button">
          <Input accept="*/*" type="file" id="file-selector-button" onChange={onFileChange} />
          <Button variant="contained" color="primary" component="span">.reg 파일 선택</Button>
        </label>
        <Box gridRow={1} width="xs" component="span" style={{ "marginLeft": "1em" }} />
        <WrappedButton variant="contained" color="primary" disabled={!executeRecaptcha || !wasm} files={files} onClick={onClick}>설정 업로드</WrappedButton>
      </Grid>
      {
        alertComponent ? (
          <Snackbar open onClose={() => setAlertComponent(undefined)} TransitionComponent={Slide}>
            {alertComponent}
          </Snackbar>
        ) : (<></>)
      }
    </Stack>
  );
}

const DownloadForm: React.FC<IGoogleReCaptchaConsumerProps & WasmProps> = ({ executeRecaptcha, wasm }) => {
  const nameRef = React.useRef<HTMLInputElement>(null);
  const passwordRef = React.useRef<HTMLInputElement>(null);
  const [mmap, setMmap] = React.useState<boolean>(false);
  const [inProgress, setInprogress] = React.useState<boolean>(false);
  const memoryInGigabytesRef = React.useRef<HTMLInputElement>(null);
  const [alertComponent, setAlertComponent] = React.useState<React.ReactElement | undefined>(undefined);
  const onClick = React.useCallback(async () => {
    if (executeRecaptcha === undefined) {
      return;
    }

    if (!inProgress) {
      setInprogress(true);
    }
  }, [executeRecaptcha, inProgress]);

  React.useEffect(() => {
    if (!inProgress || executeRecaptcha === undefined) {
      return;
    }

    (async () => {
      const token = await executeRecaptcha();
      try {
        try {
          let mem = Number.parseInt(memoryInGigabytesRef.current?.value ?? "4", 10);
          const payload =
            await wasm.store_get(
              nameRef.current!!.value,
              passwordRef.current!!.value,
              token,
              mmap,
              mem,
            );

          const normalizedName = nameRef.current!!.value.replaceAll(/[^a-zA-Z0-9\-_]/g, "");
          const element = document.createElement("a");
          const file = new Blob([payload], { type: "*/*" });
          element.href = URL.createObjectURL(file);
          element.download = `maplestory_settings_${normalizedName}_${Math.floor(Date.now() / 1000)}.reg`;
          element.hidden = true;
          document.body.appendChild(element);
          try {
            element.click();
          } finally {
            document.body.removeChild(element);
          }
        } catch (e: any) {
          const errorAlert = (<Alert onClose={() => setAlertComponent(undefined)} severity="error" sx={{ width: "100%" }}>
            {`다운로드에 실패하였습니다: ${String(e)}`}
          </Alert>);
          setAlertComponent(errorAlert);
          throw e;
        }
      } finally {
        setInprogress(false);
      }

    })();
  }
    , [executeRecaptcha, wasm, mmap, inProgress]);

  return (
    <Stack className="id-pw-input" spacing={2} width="sm">
      <Typography variant="h5">설정 다운로드</Typography>
      <TextField label="이름" variant="filled" inputRef={nameRef}></TextField>
      <TextField label="비밀번호" variant="outlined" type="password" inputRef={passwordRef}></TextField>
      <FormControl component="fieldset">
        <FormLabel component="legend">메모리 맵 입출력</FormLabel>
        <RadioGroup row defaultValue="no" onChange={ev => setMmap(ev.target.value === "yes")}>
          <FormControlLabel label="사용" value="yes" control={<Radio />} />
          <FormControlLabel label="미사용" value="no" control={<Radio />} />
        </RadioGroup>
      </FormControl>
      <TextField label="최대 메모리 사용량" variant="outlined" type="number"
        InputProps={{ endAdornment: (<InputAdornment position="end">GB</InputAdornment>) }}
        inputRef={memoryInGigabytesRef}
        defaultValue={(navigator as unknown as { deviceMemory: number | undefined }).deviceMemory ?? 4}
        disabled={mmap}></TextField>
      <Grid container justifyContent="flex-end">
        {inProgress ? <CircularProgress /> : <></>}
        <Box component="span" style={{ "marginLeft": "0.8em" }} />
        <Button variant="contained" color="primary" disabled={!executeRecaptcha || !wasm} onClick={onClick}>설정 다운로드</Button>
      </Grid>
      {
        alertComponent ? (
          <Snackbar open onClose={() => setAlertComponent(undefined)} TransitionComponent={Slide}>
            {alertComponent}
          </Snackbar>
        ) : (<></>)
      }
    </Stack>
  )
}

type WasmType = typeof import("./pkg");
const Forms: React.FC = () => {
  const [wasm, setWasm] = React.useState<WasmType | undefined>(undefined);
  React.useEffect(() => {
    const fetchWasm = async () => {
      const wasm = await import("./pkg");
      wasm.init();
      setWasm(wasm);
    };
    fetchWasm();
  }, []);
  const { executeRecaptcha } = useGoogleReCaptcha();

  if (wasm === undefined) {
    return (<></>);
  }

  return (
    <Container maxWidth="xl" style={{ "padding": "3em" }}>
      <Stack className="forms-container" direction="row" spacing={3} justifyContent="center" alignItems="start">
        <UploadForm executeRecaptcha={executeRecaptcha} wasm={wasm} />
        <DownloadForm executeRecaptcha={executeRecaptcha} wasm={wasm} />
      </Stack>
    </Container>
  );
}

const disclaimer_text: string =
  `이 서비스는 베타 버전으로 예고 없이 중지되거나 데이터가 유실될 수 있습니다.
   설정 파일은 업로드 후 1년간 보존되며 주어진 비밀번호를 사용해 암호화되어 저장됩니다.
   설정 파일에는 계정에 관련된 민감한 정보가 있을 수 있으므로 복잡한 비밀번호를 사용해야 합니다.
   유추하기 쉬운 이름(ex: abc)을 사용하면 다른 사람이 동일한 이름으로 설정 파일을 업로드해 덮어씌울 수 있습니다. 이 경우 이전 사람이 업로드한 파일은 삭제되고 비밀번호도 같이 덮어씌워집니다.
`;

const Disclaimer: React.FC = () => (
  <Container style={{ "marginTop": "4em" }} maxWidth="sm">
    <Stack spacing={2} justifyContent="left">
      <Typography variant="h4" style={{ "margin": "1em" }}>추가 정보</Typography>
      {
        disclaimer_text.trim().split(/\n\s+/).map((s, i) => (
          <Typography variant="body1" align="left" key={i}>
            {`${i}. ` + s}
          </Typography>
        ))
      }
    </Stack>
  </Container>
);

const Help: React.FC = () => (
  <Container maxWidth="md">
    <Typography variant="h6" align="left">
      .reg 파일 생성하는 법 (업로드)
    </Typography>
    <Typography variant="body1" align="left">1. Windows 10의 경우: [Win]+[x]를 누른 후 'Windows Powershell'을 클릭합니다.</Typography>
    <Typography variant="body1" align="left">2. Windows 10 미만 버전의 경우: 시작에서 'Windows Powershell'을 검색해 실행합니다.</Typography>
    <Typography variant="body1" align="left">3. 다음 명령어를 입력합니다.</Typography>
    <Typography variant="body2" noWrap align="left">
      <pre style={{ "overflow": "auto", "padding": "1em", "background": "whiteSmoke", "border": "1px solid gray", "borderRadius": "0.4em" }}>reg export HKLM\SOFTWARE\WOW6432Node\Wizet\MapleStory $Env:USERPROFILE\Desktop\maplestory.reg /y</pre>
    </Typography>
    <Typography variant="body1" align="left">4. 바탕화면에서 <pre style={{ "display": "inline", "padding": "0.5em" }}>maplestory.reg</pre> 파일을 찾아 업로드합니다.</Typography>
    <Typography variant="h6" align="left" style={{ "marginTop": "1em" }}>
      .reg 파일 사용하는 법 (다운로드)
    </Typography>
    <Typography variant="body1" align="left">1. PC방에서 Chrome으로 이 페이지에 접속하여 이름과 비밀번호를 입력합니다.</Typography>
    <Typography variant="body1" align="left">2. PC방 컴퓨터의 메모리 사양에 맞게 메모리 관련 옵션을 조정합니다.</Typography>
    <Typography variant="body2" noWrap align="left">&nbsp;&nbsp;&nbsp;&nbsp; Tip: [Win]+[Pause] 키를 누르면 '시스템 정보'를 확인할 수 있습니다.</Typography>
    <Typography variant="body1" align="left">3. 다운로드된 설정을 더블클릭하여 해당 레지스트리 파일을 추가합니다.</Typography>
    <Typography variant="body1" align="left">4. <a href="https://maplestory.nexon.com">메이플스토리 하러 갑시다</a>.</Typography>
  </Container>
);

const Main: React.FC = () => {
  return (
    <GoogleReCaptchaProvider reCaptchaKey={process.env.REACT_APP_RECAPTCHA_KEY} language="ko">
      <ThemeProvider theme={theme}>
        <Title />
        <Forms />
        <Help />
        <Disclaimer />
      </ThemeProvider>
    </GoogleReCaptchaProvider>
  );
}

function App() {
  return (
    <div className="App">
      <Main />
    </div>
  );
}

export default App;
