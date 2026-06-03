import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Badge, Button, Card, Col, Container, Form, ListGroup, Row, Spinner } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';
import { CatalogBook, CatalogChapter, CatalogClass, catalogService } from './services/catalogService';
import { readingStateService } from './services/readingState';
import BottomNav from './components/BottomNav';

type Route =
  | { name: 'home' }
  | { name: 'class'; classId: string }
  | { name: 'subject'; classId: string; subjectId: string }
  | { name: 'book'; bookId: string }
  | { name: 'chapter'; bookId: string; chapterId: string };

const parseRoute = (): Route => {
  const hash = window.location.hash.replace(/^#/, '');
  const clean = hash.startsWith('/') ? hash.slice(1) : hash;
  const parts = clean.split('/').filter(Boolean);

  if (parts.length === 2 && parts[0] === 'class') return { name: 'class', classId: parts[1] };
  if (parts.length === 4 && parts[0] === 'class' && parts[2] === 'subject') {
    return { name: 'subject', classId: parts[1], subjectId: parts[3] };
  }
  if (parts.length === 2 && parts[0] === 'book') return { name: 'book', bookId: parts[1] };
  if (parts.length === 4 && parts[0] === 'book' && parts[2] === 'chapter') {
    return { name: 'chapter', bookId: parts[1], chapterId: parts[3] };
  }
  return { name: 'home' };
};

const navigateTo = (path: string): void => {
  window.location.hash = path;
};

const App: React.FC = () => {
  const [route, setRoute] = useState<Route>(() => parseRoute());
  const [catalog, setCatalog] = useState<CatalogClass[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [fontScale, setFontScale] = useState(100);
  const [zoom, setZoom] = useState(125);

  useEffect(() => {
    const onHashChange = () => setRoute(parseRoute());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    const loadCatalog = async () => {
      try {
        setIsLoading(true);
        setError(null);
        const data = await catalogService.getCatalog();
        setCatalog(data.classes);
      } catch (err: any) {
        setError(err?.message || 'Unable to load catalog.');
      } finally {
        setIsLoading(false);
      }
    };

    loadCatalog();
  }, []);

  const allBooks = useMemo(() => {
    return catalog.flatMap((classItem) =>
      classItem.subjects.flatMap((subject) =>
        subject.books.map((book) => ({ ...book, classId: classItem.id, subjectId: subject.id, subjectName: subject.name }))
      )
    );
  }, [catalog]);

  const continueReading = readingStateService.getContinueReading();

  const selectedClass = useMemo(
    () => (route.name === 'class' || route.name === 'subject' ? catalog.find((item) => item.id === route.classId) : null),
    [catalog, route]
  );

  const selectedSubject = useMemo(() => {
    if (route.name !== 'subject' || !selectedClass) return null;
    return selectedClass.subjects.find((subject) => subject.id === route.subjectId) ?? null;
  }, [route, selectedClass]);

  const selectedBook = useMemo(() => {
    if (route.name === 'book' || route.name === 'chapter') {
      return allBooks.find((book) => book.id === route.bookId) ?? null;
    }
    return null;
  }, [allBooks, route]);

  const selectedChapter = useMemo(() => {
    if (route.name !== 'chapter' || !selectedBook) return null;
    return selectedBook.chapters.find((chapter) => chapter.id === route.chapterId) ?? null;
  }, [route, selectedBook]);

  const openChapter = (book: CatalogBook, chapter: CatalogChapter) => {
    readingStateService.saveContinueReading({
      classId: book.classId,
      subjectId: book.subjectId,
      bookId: book.id,
      bookTitle: book.title,
      chapterId: chapter.id,
      chapterTitle: chapter.title,
      chapterUrl: chapter.url,
      chapterType: chapter.type,
      lastOpenedAt: new Date().toISOString(),
    });
    navigateTo(`/book/${book.id}/chapter/${chapter.id}`);
  };

  const readerUrl = useMemo(() => {
    if (!selectedChapter) return '';
    if (selectedChapter.type === 'pdf') {
      return `${selectedChapter.url}#zoom=${zoom}`;
    }
    return selectedChapter.url;
  }, [selectedChapter, zoom]);

  const chapterIndex = useMemo(() => {
    if (!selectedBook || !selectedChapter) return -1;
    return selectedBook.chapters.findIndex((chapter) => chapter.id === selectedChapter.id);
  }, [selectedBook, selectedChapter]);

  return (
    <div className="app-shell">
      <Container className="app-main pb-5">
        <header className="app-header py-3">
          <h1 className="mb-1">NCERT Reader</h1>
          <p className="text-muted mb-0">Read NCERT books from your GitHub-hosted catalog on your phone.</p>
        </header>

        {isLoading && (
          <div className="text-center py-5">
            <Spinner animation="border" />
            <p className="mt-2 mb-0">Loading catalog...</p>
          </div>
        )}

        {error && (
          <Alert variant="danger" className="mb-3">
            {error}
          </Alert>
        )}

        {!isLoading && !error && (
          <>
            {route.name === 'home' && (
              <Row className="g-3">
                {continueReading && (
                  <Col xs={12}>
                    <Card className="quick-card">
                      <Card.Body>
                        <Card.Title className="h6">Continue reading</Card.Title>
                        <Card.Text className="small mb-2">{continueReading.bookTitle} • {continueReading.chapterTitle}</Card.Text>
                        <Button size="sm" onClick={() => navigateTo(`/book/${continueReading.bookId}/chapter/${continueReading.chapterId}`)}>
                          Open last chapter
                        </Button>
                      </Card.Body>
                    </Card>
                  </Col>
                )}
                {catalog.map((classItem) => (
                  <Col xs={12} key={classItem.id}>
                    <Card className="tap-card" onClick={() => navigateTo(`/class/${classItem.id}`)} role="button">
                      <Card.Body>
                        <Card.Title className="mb-1">{classItem.name}</Card.Title>
                        <Card.Text className="text-muted mb-0">{classItem.subjects.length} subjects</Card.Text>
                      </Card.Body>
                    </Card>
                  </Col>
                ))}
              </Row>
            )}

            {route.name === 'class' && selectedClass && (
              <>
                <Button variant="link" className="px-0 mb-2" onClick={() => navigateTo('/')}>← Back</Button>
                <h2 className="h5 mb-3">{selectedClass.name} subjects</h2>
                <ListGroup>
                  {selectedClass.subjects.map((subject) => (
                    <ListGroup.Item
                      action
                      key={subject.id}
                      onClick={() => navigateTo(`/class/${selectedClass.id}/subject/${subject.id}`)}
                      className="py-3"
                    >
                      {subject.name} <Badge bg="secondary" pill>{subject.books.length}</Badge>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              </>
            )}

            {route.name === 'subject' && selectedClass && selectedSubject && (
              <>
                <Button variant="link" className="px-0 mb-2" onClick={() => navigateTo(`/class/${selectedClass.id}`)}>← Back</Button>
                <h2 className="h5 mb-3">{selectedClass.name} / {selectedSubject.name}</h2>
                <Row className="g-3">
                  {selectedSubject.books.map((book) => (
                    <Col xs={12} key={book.id}>
                      <Card className="tap-card" onClick={() => navigateTo(`/book/${book.id}`)} role="button">
                        <Card.Body>
                          <Card.Title className="mb-1">{book.title}</Card.Title>
                          <Card.Text className="text-muted small mb-0">{book.chapters.length} chapters</Card.Text>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
              </>
            )}

            {route.name === 'book' && selectedBook && (
              <>
                <Button variant="link" className="px-0 mb-2" onClick={() => navigateTo(`/class/${selectedBook.classId}/subject/${selectedBook.subjectId}`)}>← Back</Button>
                <h2 className="h5">{selectedBook.title}</h2>
                {selectedBook.description && <p className="text-muted small">{selectedBook.description}</p>}
                <ListGroup>
                  {selectedBook.chapters.map((chapter) => (
                    <ListGroup.Item action key={chapter.id} onClick={() => openChapter(selectedBook, chapter)} className="py-3">
                      {chapter.title}
                      <Badge bg="light" text="dark" className="ms-2">{chapter.type.toUpperCase()}</Badge>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              </>
            )}

            {route.name === 'chapter' && selectedBook && selectedChapter && (
              <>
                <Button variant="link" className="px-0 mb-2" onClick={() => navigateTo(`/book/${selectedBook.id}`)}>← Chapters</Button>
                <Card className="mb-3">
                  <Card.Body>
                    <div className="d-flex justify-content-between gap-2 align-items-center flex-wrap">
                      <div>
                        <h2 className="h6 mb-1">{selectedChapter.title}</h2>
                        <p className="small text-muted mb-0">{selectedBook.title}</p>
                      </div>
                      <Button
                        size="sm"
                        variant="outline-primary"
                        onClick={() => readingStateService.toggleBookmark(selectedBook.id, selectedChapter.id)}
                      >
                        {readingStateService.isBookmarked(selectedBook.id, selectedChapter.id) ? 'Bookmarked' : 'Bookmark'}
                      </Button>
                    </div>
                    <div className="reader-controls mt-3">
                      <Form.Label className="small mb-1">Reader font: {fontScale}%</Form.Label>
                      <Form.Range min={90} max={140} step={5} value={fontScale} onChange={(e) => setFontScale(Number(e.target.value))} />
                      <Form.Label className="small mb-1">PDF zoom: {zoom}%</Form.Label>
                      <Form.Range min={80} max={200} step={5} value={zoom} onChange={(e) => setZoom(Number(e.target.value))} />
                    </div>
                  </Card.Body>
                </Card>

                <div className="reader-frame" style={{ fontSize: `${fontScale}%` }}>
                  <iframe title={selectedChapter.title} src={readerUrl} className="chapter-frame" loading="lazy" />
                </div>

                <div className="d-flex justify-content-between mt-3 gap-2">
                  <Button
                    variant="outline-secondary"
                    disabled={chapterIndex <= 0}
                    onClick={() => chapterIndex > 0 && openChapter(selectedBook, selectedBook.chapters[chapterIndex - 1])}
                  >
                    Previous
                  </Button>
                  <Button
                    disabled={chapterIndex >= selectedBook.chapters.length - 1}
                    onClick={() => chapterIndex < selectedBook.chapters.length - 1 && openChapter(selectedBook, selectedBook.chapters[chapterIndex + 1])}
                  >
                    Next
                  </Button>
                </div>
              </>
            )}
          </>
        )}
      </Container>
      <BottomNav
        onHome={() => navigateTo('/')}
        onContinue={() => {
          if (continueReading) {
            navigateTo(`/book/${continueReading.bookId}/chapter/${continueReading.chapterId}`);
          }
        }}
        disableContinue={!continueReading}
      />
    </div>
  );
};

export default App;
